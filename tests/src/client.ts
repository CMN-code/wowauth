// tests/src/client.ts
import createClient from "openapi-fetch";
import type { paths } from "../schema/api.d.ts";
import { adminHeaders, BASE_URL } from "./test-env.ts";

export const client = createClient<paths>({ baseUrl: BASE_URL, headers: adminHeaders });
