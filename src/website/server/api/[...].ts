export default defineEventHandler(async (event) => {
		const config = useRuntimeConfig();

		const address = apiAddress(config.apiAddress, config.public.abandonAuthUrl);
		const { target, options } = apiProxyRequest(address, event.path);
		return proxyRequest(event, target, options);
});
