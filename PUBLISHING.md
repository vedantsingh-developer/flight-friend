# Publish Flight Friend with real email and phone verification

This deploy runs the Flight Friend website and backend at one HTTPS origin. The package includes Firebase Authentication support for verified email and phone sign-in. The Firebase project settings must be supplied by the project owner; no credentials are embedded in this download.

## Prepare Firebase

1. In Firebase Console, create a project and register a Web app. Copy its public Web configuration values: `apiKey`, `authDomain`, `projectId`, and `appId`. Never put a service-account key or private key in this website.
2. Enable Email/Password and Phone sign-in under Authentication. Set the SMS region policy to India.
3. Add the final hosted domain to Firebase Authentication's authorized domains. Phone verification also uses reCAPTCHA.
4. Phone verification SMS can incur charges and may require pay-as-you-go billing. Check Firebase's current pricing and set a budget alert before enabling SMS.

## Deploy with Render

1. Put the contents of this folder at the root of a **private** GitHub repository.
2. In Render, create a Blueprint from that repository and use `render.yaml`.
3. When asked for protected values, provide the Firebase project ID and Web API key, a developer username, and a strong unique developer password. Render generates the database encryption and lookup keys.
4. `public/index.html` already contains the Firebase Web app configuration supplied for Flight Friend. Confirm it matches the intended Firebase project before deployment; keep any service-account keys out of the repository.
5. Confirm the deployed site uses HTTPS, then add its exact domain to Firebase's authorized domains.
6. Open `/admin/` on the hosted site and sign in with the developer credentials. Share only the HTTPS website address with visitors.

Keep the source repository private and enable two-step verification on GitHub, Render, and Firebase. This app uses SQLite on a persistent disk and expects one running instance. Review Render's current plan and disk pricing before deployment.

## Local setup

For the local prototype, extract the package and run `setup.cmd`, then `run.cmd`. Setup uses an installed compatible Node version or downloads the official standalone runtime and verifies its checksum. It does not run the Windows Node installer.

## Important limits

An HTML file sent as an attachment cannot share a backend or perform real email/SMS verification. A hosted HTTPS site is required. No site has been published by this package itself; a deploy is complete only after you configure Firebase and a hosting project.

The prototype has no live order/payment flow, airline/rail itinerary verification, or Aadhaar verification. Terms and privacy copy are drafts; have them reviewed and publish operator/support details before public launch.

