"""Explicit Cost Explorer windows, Decimal aggregation and currency separation."""
from collections import defaultdict
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from .eks_cli import CollectionError

METRICS = {'UnblendedCost', 'AmortizedCost', 'NetUnblendedCost', 'NetAmortizedCost'}


def validate(start, end, metric, granularity):
    try:
        left, right = date.fromisoformat(start), date.fromisoformat(end)
        if start != left.isoformat() or end != right.isoformat():
            raise ValueError()
    except (ValueError, TypeError):
        raise CollectionError('invalid_cost_dates') from None
    if not 0 < (right-left).days <= 366 or right > datetime.now(timezone.utc).date():
        raise CollectionError('cost_window_max_366_days_end_not_future')
    if metric not in METRICS or granularity not in {'DAILY', 'MONTHLY'}:
        raise CollectionError('unsupported_cost_metric_or_granularity')


def collect(context, result, start_date, end_date, metric='UnblendedCost', granularity='MONTHLY',
            organization_scope=False, usage_region=''):
    validate(start_date, end_date, metric, granularity)
    filters = []
    if not organization_scope:
        filters.append({'Dimensions': {'Key': 'LINKED_ACCOUNT', 'Values': [context.account_id]}})
    if usage_region:
        filters.append({'Dimensions': {'Key': 'REGION', 'Values': [usage_region]}})
    params = {'TimePeriod': {'Start': start_date, 'End': end_date}, 'Granularity': granularity,
              'Metrics': [metric], 'GroupBy': [{'Type': 'DIMENSION', 'Key': 'SERVICE'}]}
    if filters:
        params['Filter'] = filters[0] if len(filters) == 1 else {'And': filters}
    result['summary'].update(start=start_date, end_exclusive=end_date, metric=metric,
                             billing_scope='caller_visible_billing_view' if organization_scope else 'authenticated_account',
                             usage_region=usage_region or 'all', aggregate_totals_verified=False)
    totals, services, estimated, seen = defaultdict(Decimal), defaultdict(Decimal), False, set()
    for period in context.pages('ce', 'get_cost_and_usage', 'ResultsByTime', **params):
        estimated = estimated or bool(period.get('Estimated', True))
        for group in period.get('Groups', []):
            if len(result['items']) >= 1000:
                raise CollectionError('cost_group_limit')
            values = group['Metrics'][metric]
            try:
                if len(values['Amount']) > 64:
                    raise InvalidOperation()
                amount = Decimal(values['Amount'])
                if not amount.is_finite() or amount.adjusted()>24 or amount.as_tuple().exponent < -18:
                    raise InvalidOperation()
            except (InvalidOperation, ValueError, TypeError):
                raise CollectionError('invalid_cost_amount') from None
            if len(group.get('Keys', [])) != 1:
                raise CollectionError('unexpected_cost_group')
            service, unit = group['Keys'][0], values['Unit']
            if not isinstance(service, str) or len(service)>256 or not isinstance(unit, str) or not 1<=len(unit)<=16:
                raise CollectionError('invalid_cost_group_metadata')
            key = (period['TimePeriod']['Start'], period['TimePeriod']['End'], service, unit)
            if key in seen:
                raise CollectionError('duplicate_cost_group')
            seen.add(key)
            with localcontext() as decimal_context:
                decimal_context.prec = 80
                totals[unit] += amount
                services[(unit, service)] += amount
            result['items'].append({'kind': 'service_cost', 'service': service, 'amount': str(amount),
                                    'unit': unit, 'metric': metric, 'estimated': bool(period.get('Estimated', True)),
                                    'period': period['TimePeriod']})
    result['summary'].update(totals_by_currency={k: str(v) for k,v in totals.items()}, estimated=estimated,
                             observed_groups=len(seen), aggregate_totals_verified=True,
                             top_services=[{'service': service, 'unit': unit, 'amount': str(amount)}
                                           for (unit, service), amount in sorted(services.items(), key=lambda row: row[1], reverse=True)[:10]],
                             assessment='observed_billing_costs', savings_verified=False)
    result['coverage'].update(service_scope='Cost Explorer global; REGION filter is usage region',
                              exclusions=['forecast', 'invoice reconciliation', 'resource attribution',
                                          'rightsizing recommendations', 'proven savings', 'payer visibility beyond caller access'])
    if not seen:
        result['summary']['assessment'] = 'no_cost_groups_returned'
        result['summary']['aggregate_totals_verified'] = False
        result['coverage']['complete'] = False
