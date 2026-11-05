export default defineEventHandler((event) => {
  const headers = authorizationPageHeaders(getRequestURL(event).pathname);

  if (headers !== undefined) {
    setResponseHeaders(event, headers);
  }
});
