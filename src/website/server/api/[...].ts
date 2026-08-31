export default defineEventHandler(async (event) => {
		const config = useRuntimeConfig();

		const { target, options } = apiProxyRequest(config.public.abandonAuthUrl, event.path);
		return proxyRequest(event, target, options);
});
