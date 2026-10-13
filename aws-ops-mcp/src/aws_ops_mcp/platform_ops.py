"""New module facade and bounded multi-scope asynchronous jobs; EKS contracts unchanged."""
import copy
import os
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import costs, organization, topology, iam_roles, dns_config, resource_assessments, security_findings, observability, deployments, applications
from . import autoscaling, optimizer
from .aws import authenticated_session
from .contracts import bounded, envelope
from .ops_runtime import ReadContext, safe_error


class Platform:
    def __init__(self, store, factory=authenticated_session, clock=time.monotonic):
        self.store, self.factory, self.clock = store, factory, clock

    def query(self, account, region, analysis, **params):
        result = envelope(account, region)
        result['items'] = []
        result['coverage'].update(fresh=True, cache_age_seconds=0)
        context = None
        try:
            collectors={'organization':organization,'cost':costs,'network':topology,'iam_role':iam_roles,'dns':dns_config,
                        'security_findings':security_findings,'incident':observability,'autoscaling':autoscaling,'optimizer':optimizer}
            resources={kind:getattr(resource_assessments,kind) for kind in ('compute','database','storage','backup')}
            resources.update({kind:getattr(deployments,kind) for kind in ('cloudformation','ecs')})
            resources.update({kind:getattr(applications,kind) for kind in ('serverless','analytics','ai')})
            if analysis not in collectors and analysis not in resources:
                raise ValueError('unsupported analysis')
            if analysis == 'cost':
                costs.validate(params['start_date'], params['end_date'],
                               params.get('metric', 'UnblendedCost'), params.get('granularity', 'MONTHLY'))
            elif analysis=='optimizer':optimizer.validate(params.get('instance_ids',[]),params.get('maximum_age_hours',168))
            elif analysis=='autoscaling':autoscaling.validate(params.get('group_name',''))
            elif analysis=='network':topology.validate(params.get('vpc_ids',[]))
            elif analysis=='iam_role':iam_roles.validate(params.get('role_name',''))
            elif analysis=='dns':dns_config.validate(params.get('hosted_zone_id',''),params.get('record_name',''))
            elif analysis in {'cloudformation','ecs'}:deployments.validate(analysis,params)
            elif analysis in {'serverless','analytics','ai'}:applications.validate(analysis,params)
            elif analysis in resources:resource_assessments.validate(analysis,params)
            elif analysis=='security_findings':security_findings.validate(params.get('services',[]),params.get('minimum_severity',4))
            elif analysis=='incident':observability.validate(params.get('alarm_prefix',''),params.get('resource_name',''),
                params.get('start_time',''),params.get('end_time',''),params.get('include_cloudtrail',True))
            context = ReadContext(account, region, self.factory, self.clock)
            result['account_id'] = context.account_id
            if analysis in resources:resources[analysis](context,result,**params)
            else:collectors[analysis].collect(context, result, **params)
        except Exception as exc:
            result['errors'].append({'code': safe_error(exc), 'component': analysis})
        if context:
            result['summary']['api_calls'] = context.calls
            result['coverage']['audit_enabled'] = bool(os.environ.get('AWS_OPS_AUDIT_FILE'))
            result['coverage']['audit_recorded'] = context.audit_ok if result['coverage']['audit_enabled'] else False
            if not context.audit_ok:
                result['errors'].append({'code': 'audit_unavailable', 'component': 'local_audit'})
            result['items'].extend({'kind': 'api_source', **row} for row in context.sources)
        if result['errors']:
            result['coverage']['complete'] = False
            result['status'] = 'partial' if result['items'] else 'error'
            result['summary']['assessment'] = 'insufficient_evidence'
            if analysis == 'cost':
                result['summary']['aggregate_totals_verified'] = False
        elif not result['coverage']['complete']:
            result['status'] = 'partial'
        elif result['findings']:
            result['status'] = 'degraded'
        result['summary']['evidence_items'] = len(result['items']) + len(result['findings'])
        result['summary']['finding_count'] = len(result['findings'])
        if result['items']:
            rows = result['items'] + [{'kind':'finding', **finding} for finding in result['findings']]
            identifier = self.store.put(account, region, rows, result['coverage'])
            if identifier:
                result['evidence_id'] = identifier
            else:
                result['errors'].append({'code': 'evidence_unavailable'})
                result['coverage']['complete'] = False
                result['status'] = 'partial'
        return bounded(result)


class OperationsJobs:
    def __init__(self, platform, clock=time.monotonic):
        self.platform, self.clock = platform, clock
        self.jobs = OrderedDict()
        self.lock = threading.RLock()

    def _expire(self):
        for key in list(self.jobs):
            finish = self.jobs[key]['finished']
            if finish is not None and self.clock() - finish > 900:
                del self.jobs[key]

    def start(self, scopes, analysis, **params):
        result = envelope()
        try:
            if analysis not in {'organization', 'cost','network','iam_role'} or not 1 <= len(scopes) <= 4:
                raise ValueError()
            # Both initial modules are global. Authentication region must not duplicate billing.
            keys=[(s['account'],s['region']) if analysis=='network' else s['account'] for s in scopes]
            if len(set(keys)) != len(scopes):
                raise ValueError()
            if analysis == 'cost':
                costs.validate(params['start_date'], params['end_date'], params.get('metric', 'UnblendedCost'),
                               params.get('granularity', 'MONTHLY'))
            elif analysis=='network':topology.validate(params.get('vpc_ids',[]))
            elif analysis=='iam_role':iam_roles.validate(params.get('role_name',''))
        except Exception:
            result.update(status='error', errors=[{'code': 'invalid_operations_scope_or_parameters'}])
            result['coverage']['complete'] = False
            return result
        with self.lock:
            self._expire()
            if sum(j['finished'] is None for j in self.jobs.values()) >= 2:
                result.update(status='error', errors=[{'code': 'operations_capacity_reached'}])
                result['coverage']['complete'] = False
                return result
            while len(self.jobs) >= 20:
                key = next(k for k,j in self.jobs.items() if j['finished'] is not None)
                del self.jobs[key]
            identifier = secrets.token_urlsafe(24)
            job = {'analysis': analysis, 'scopes': copy.deepcopy(scopes), 'results': {}, 'finished': None}
            self.jobs[identifier] = job
            threading.Thread(target=self._run, args=(identifier, job, copy.deepcopy(params)), daemon=True).start()
        return self.get(identifier)

    def _run(self, identifier, job, params):
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks = {pool.submit(self.platform.query, scope['account'], scope['region'], job['analysis'], **params): i
                     for i,scope in enumerate(job['scopes'])}
            for future in as_completed(tasks):
                index = tasks[future]
                try:
                    value = future.result()
                except Exception:
                    value = envelope(job['scopes'][index]['account'], job['scopes'][index]['region'])
                    value.update(status='error', errors=[{'code': 'operations_worker_error'}])
                    value['coverage']['complete'] = False
                with self.lock:
                    job['results'][index] = value
        with self.lock:
            job['finished'] = self.clock()

    def get(self, identifier):
        result = envelope()
        with self.lock:
            self._expire()
            job = self.jobs.get(identifier)
            if not job:
                result.update(status='error', errors=[{'code': 'operations_missing_or_expired'}])
                result['coverage']['complete'] = False
                return result
            running = job['finished'] is None
            result['investigation_id'] = identifier
            result['summary'] = {'state': 'running' if running else 'finished', 'analysis': job['analysis'],
                                 'completed_scopes': len(job['results']), 'requested_scopes': len(job['scopes']),
                                 'cross_scope_money_totals_aggregated': False}
            result['items'] = [copy.deepcopy(job['results'][i]) for i in sorted(job['results'])]
        complete = not running and all(r['coverage']['complete'] and r['status'] not in {'error', 'partial'}
                                       for r in result['items'])
        result['coverage']['complete'] = complete
        result['status'] = ('degraded' if any(r['status']=='degraded' for r in result['items']) else 'ok') if complete else 'partial'
        # Keep all four scope summaries and evidence references under the outer budget.
        for scope in result['items']:
            scope.pop('items', None)
            scope['findings'] = scope.get('findings', [])[:3]
            scope['errors'] = scope.get('errors', [])[:3]
            if 'top_services' in scope.get('summary', {}):
                scope['summary']['top_services'] = scope['summary']['top_services'][:3]
        return bounded(result)
