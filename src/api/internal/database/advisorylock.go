package database

// AdvisoryLockKey serialises two operations: deciding what the schema is and
// migrating it, and rotating the value every issued credential is stamped with.
//
// Both change what the database treats as authoritative, and neither may run
// while the other does. They share one key rather than taking one each.
const AdvisoryLockKey int64 = 7013500273095901185
