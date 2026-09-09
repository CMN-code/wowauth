// Nmbrs-specific constants. See docs/examples/NMBRS.md and
// docs/examples/nmbrs-setup.ts for the scripted, narrated equivalent of the
// wizard this file backs.

export const NMBRS_AUTH_URL = "https://identityservice.nmbrs.com/connect/authorize";
export const NMBRS_TOKEN_URL = "https://identityservice.nmbrs.com/connect/token";

// offline_access is mandatory -- without it Nmbrs never issues a refresh
// token, and wowauth would have nothing to renew with once the access token
// expires. Always requested, not part of the scope picker.
export const NMBRS_MANDATORY_SCOPES = ["offline_access"];

// The full read-only-and-otherwise scope set Nmbrs documents for partner
// apps. Deliberately no "openid": Nmbrs doesn't grant it to partner-app
// clients, and requesting it is a common cause of "Invalid scope" errors.
export const NMBRS_OPTIONAL_SCOPES = [
  "employee.employment",
  "employee.employment.read",
  "employee.info",
  "employee.info.read",
  "employee.payment",
  "employee.payment.read",
  "employee.leave",
  "employee.leave.read",
  "employee.orgstructure",
  "employee.orgstructure.read",
  "employee.bankaccount.read",
  "employee.bankaccount",
  "employee.document.read",
  "employee.document",
  "employee.payrollsettings",
  "employee.payrollsettings.read",
  "company.info",
  "company.info.read",
  "company.payrollsettings.read",
  "company.leave.read",
  "user.info.read",
];

// A light, read-only call used at the very end to prove the connection
// actually works against real Nmbrs data.
export const NMBRS_SMOKE_TEST_URL = "https://api.nmbrsapp.com/api/companies";

export const NMBRS_PARTNER_PORTAL_URL = "https://partner-portal.nmbrsapp.com/integrations";
export const NMBRS_SUBSCRIPTION_PROFILE_URL = "https://developer.payroll.nmbrs.com/profile";
export const NMBRS_ICON_URL =
  "https://cdn.prod.website-files.com/664d8603947eced5ca9765b0/664dd23030ceb92425696ff4_CMN-logo-footer.svg";
