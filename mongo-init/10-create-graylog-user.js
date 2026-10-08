// Runs once, when the MongoDB data volume is empty (docker-entrypoint-initdb.d).
// Creates a least-privilege user for Graylog; the password comes from the environment.
const password = process.env.MONGODB_GRAYLOG_PASSWORD;
if (!password) {
  throw new Error('MONGODB_GRAYLOG_PASSWORD is not set');
}
db.getSiblingDB('graylog').createUser({
  user: 'graylog',
  pwd: password,
  roles: [
    { role: 'readWrite', db: 'graylog' },
    { role: 'dbAdmin', db: 'graylog' },
  ],
});
