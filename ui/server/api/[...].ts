import {joinURL} from "ufo";

export default defineEventHandler(async (event) => {
		const config = useRuntimeConfig();

		const target = joinURL(config.public.abandonAuthUrl, event.path);
		return proxyRequest(event, target);
});
