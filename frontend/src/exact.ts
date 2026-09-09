// Exact Online-specific constants. See docs/examples/exact-setup.ts for the
// scripted, narrated equivalent of the wizard this file backs.

// Exact runs the identical API under a different top-level domain per
// country -- there's no single global endpoint. Picking the wrong one just
// means the login page rejects the account as unknown, not a security
// problem.
export const EXACT_COUNTRIES: { label: string; domain: string }[] = [
  { label: "Netherlands", domain: "start.exactonline.nl" },
  { label: "Belgium", domain: "start.exactonline.be" },
  { label: "Germany", domain: "start.exactonline.de" },
  { label: "United Kingdom", domain: "start.exactonline.co.uk" },
  { label: "France", domain: "start.exactonline.fr" },
  { label: "Spain", domain: "start.exactonline.es" },
  { label: "United States / rest of world", domain: "start.exactonline.com" },
];

export const EXACT_APP_CENTER_URL = "https://start.exactonline.nl";

// A light, read-only call used at the end to prove the connection actually
// works against real Exact data -- also the standard way to discover which
// "division" (administration) a token defaults to, since Exact accounts can
// see more than one.
export const EXACT_ME_PATH = "/api/v1/current/Me";
