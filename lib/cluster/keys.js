'use strict';

// Redis keys of the instance cluster. Dependency-free apart from the key prefix, so the account
// deletion pipeline and the pure tests can name the same keys the coordinator writes.
//
//   cluster:inst:<id>      hash, one per live instance, expires unless its heartbeat renews it
//   cluster:instances      set of instance ids that registered; pruned of ids whose hash expired
//   cluster:own:<account>  string, the id of the instance that owns the account, no expiry: an
//                          account is owned while that instance's hash is alive
//   cluster:secret         string, the key every cluster call is signed with
//   cluster:bus            pub/sub channel the instances broadcast on

const { REDIS_PREFIX } = require('../consts');

const clusterKeys = {
    instances: `${REDIS_PREFIX}cluster:instances`,
    secret: `${REDIS_PREFIX}cluster:secret`,
    bus: `${REDIS_PREFIX}cluster:bus`,
    instance: id => `${REDIS_PREFIX}cluster:inst:${id}`,
    owner: account => `${REDIS_PREFIX}cluster:own:${account}`,
    account: account => `${REDIS_PREFIX}iad:${account}`,
    accounts: `${REDIS_PREFIX}ia:accounts`
};

module.exports = { clusterKeys };
