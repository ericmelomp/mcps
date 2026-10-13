"""Alarm snapshots and management-event timeline; temporal co-occurrence is not causality."""
import json
from collections import Counter
from datetime import datetime,timezone,timedelta
from .security import utc
from .ops_runtime import safe_error
from .eks_cli import CollectionError


def validate(alarm_prefix,resource_name,start_time,end_time,include_cloudtrail=True):
    if not isinstance(alarm_prefix,str) or not 1<=len(alarm_prefix)<=128 or any(ord(c)<32 for c in alarm_prefix):
        raise CollectionError('invalid_alarm_prefix')
    if include_cloudtrail:
        if not isinstance(resource_name,str) or not 1<=len(resource_name)<=256 or any(ord(c)<32 for c in resource_name):
            raise CollectionError('invalid_cloudtrail_resource_name')
        start,end=utc(start_time),utc(end_time);now=datetime.now(timezone.utc)
        if not timedelta(0)<end-start<=timedelta(hours=24) or start<now-timedelta(days=90) or end>now:
            raise CollectionError('incident_window_max_24h_within_90_days')


def collect(context,result,alarm_prefix,resource_name='',start_time='',end_time='',include_cloudtrail=True):
    states=Counter();events=Counter();denied=0
    try:
        for kind,key in [('MetricAlarm','MetricAlarms'),('CompositeAlarm','CompositeAlarms')]:
            for alarm in context.pages('cloudwatch','describe_alarms',key,AlarmNamePrefix=alarm_prefix,AlarmTypes=[kind],MaxRecords=100):
                if len(result['items'])>=1000:raise CollectionError('observability_item_limit')
                state=alarm.get('StateValue','unknown');states[state]+=1
                stamp=alarm.get('StateUpdatedTimestamp')
                result['items'].append({'kind':'alarm_state','resource_id':alarm['AlarmArn'],'alarm_type':kind,
                    'state':state,'state_updated_at':stamp.isoformat() if isinstance(stamp,datetime) else None,
                    'actions_enabled':alarm.get('ActionsEnabled'),'namespace':alarm.get('Namespace')})
                if state in {'ALARM','INSUFFICIENT_DATA'}:
                    result['findings'].append({'code':'alarm_state_requires_review','resource_id':alarm['AlarmArn'],
                        'severity':'warning' if state=='ALARM' else 'info','confidence':'confirmed',
                        'evidence':{'state':state},'recommendations':['Inspect metric history and the intended alarm thresholds']})
    except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':'alarms'})
    if include_cloudtrail:
        start,end=utc(start_time),utc(end_time)
        try:
            for event in context.pages('cloudtrail','lookup_events','Events',LookupAttributes=[{'AttributeKey':'ResourceName','AttributeValue':resource_name}],
                StartTime=start,EndTime=end,MaxResults=50):
                if len(result['items'])>=1000:raise CollectionError('observability_item_limit')
                events[event['EventName']]+=1
                permission_denied=False;other_error=False;classification_verified=True
                try:
                    text=event.get('CloudTrailEvent','{}')
                    if not isinstance(text,str) or len(text)>256*1024:raise ValueError()
                    raw=json.loads(text)
                    if not isinstance(raw,dict):raise ValueError()
                    error=raw.get('errorCode')
                    permission_denied=isinstance(error,str) and error in {'AccessDenied','AccessDeniedException','UnauthorizedOperation','Client.UnauthorizedOperation'}
                    other_error=bool(error) and not permission_denied
                except (ValueError,TypeError,RecursionError):
                    permission_denied=None;other_error=None;classification_verified=False
                    result['errors'].append({'code':'cloudtrail_event_parse_failed','component':'cloudtrail'})
                    if len(result['errors'])>=20:raise CollectionError('component_error_limit')
                denied+=permission_denied is True
                stamp=event.get('EventTime')
                result['items'].append({'kind':'management_event','event_id':event['EventId'],'event_name':event['EventName'],
                    'event_source':event.get('EventSource'),'event_time':stamp.isoformat() if isinstance(stamp,datetime) else None,
                    'permission_denied':permission_denied,'other_error':other_error,'error_classification_verified':classification_verified})
        except Exception as exc:result['errors'].append({'code':safe_error(exc),'component':'cloudtrail'})
    result['summary'].update(alarm_states=dict(states),management_event_counts=dict(events.most_common(10)),
        permission_denied_events=denied,root_cause_verified=False,assessment='alarm_snapshot_and_management_timeline',
        interpretation='Alarm snapshot and selected management events do not establish a causal connection')
    result['coverage']['exclusions']=['alarm state history','data events','Logs Insights/traces','actual metric values',
                                     'CloudTrail beyond regional Event History','event payloads/user identities','confirmed root cause']
