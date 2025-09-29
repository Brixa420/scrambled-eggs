# Production Deployment Checklist

## Pre-Deployment

### Infrastructure
- [ ] Verify cloud provider quotas and limits
- [ ] Ensure all required services are provisioned
  - [ ] Compute instances
  - [ ] Database
  - [ ] Cache
  - [ ] Object storage
  - [ ] CDN
- [ ] Verify backup and disaster recovery procedures
- [ ] Confirm monitoring and alerting are configured

### Application
- [ ] Update environment variables
- [ ] Run database migrations
- [ ] Invalidate CDN caches if needed
- [ ] Prepare rollback plan

### Testing
- [ ] Run full test suite
- [ ] Test database migrations on staging
- [ ] Verify backup restoration process

## Deployment

### Process
1. **Start deployment during low-traffic period**
2. **Deploy to canary environment** (if applicable)
   - [ ] Monitor for errors
   - [ ] Verify functionality
3. **Gradual rollout**
   - [ ] Deploy to 10% of instances
   - [ ] Monitor metrics
   - [ ] Increase to 50%
   - [ ] Full deployment

### Verification
- [ ] Check application health endpoints
- [ ] Verify all services are running
- [ ] Test critical user journeys
- [ ] Monitor error rates and performance

## Post-Deployment

### Monitoring
- [ ] Check application logs
- [ ] Monitor error rates
- [ ] Verify metrics collection
- [ ] Check alerting channels

### Communication
- [ ] Update status page
- [ ] Notify stakeholders
- [ ] Update documentation

## Rollback Plan

### Automated Rollback Triggers
- 5xx errors > 5% for 5 minutes
- Latency > 2s p99
- Failed health checks

### Manual Rollback Steps
1. Revert to previous container image
2. Rollback database migrations if needed
3. Clear CDN caches
4. Verify rollback success

## Maintenance

### Regular Checks
- [ ] Backup verification
- [ ] Security patches
- [ ] Dependency updates
- [ ] Certificate renewal

### Scale Up/Down
- [ ] Monitor autoscaling metrics
- [ ] Adjust resource allocations
- [ ] Update capacity planning

## Incident Response

### On-Call Rotation
- [ ] Primary on-call assigned
- [ ] Secondary on-call notified
- [ ] Escalation paths defined

### Communication Channels
- [ ] Status page updates
- [ ] Internal notifications
- [ ] Customer communications

## Security

### Access Control
- [ ] Principle of least privilege
- [ ] Multi-factor authentication
- [ ] Audit logs enabled

### Data Protection
- [ ] Encryption at rest
- [ ] Encryption in transit
- [ ] Key rotation schedule

## Performance

### Baseline Metrics
- [ ] Response times
- [ ] Throughput
- [ ] Error rates
- [ ] Resource utilization

### Optimization
- [ ] Query optimization
- [ ] Caching strategy
- [ ] CDN configuration

## Documentation

### System Architecture
- [ ] Updated diagrams
- [ ] Service dependencies
- [ ] Data flow documentation

### Runbooks
- [ ] Common procedures
- [ ] Troubleshooting guides
- [ ] Contact information
