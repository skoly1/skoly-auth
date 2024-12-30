export interface Component {
  name: string;
  description: string;
  files: string[];
  dependencies: Record<string, string>;
}

export const components: Record<string, Component> = {
  "password-login": {
    name: "Password Login",
    description: "Email and password based authentication",
    files: ["components/PasswordLogin.tsx", "lib/auth/password.ts"],
    dependencies: {
      "@skoly/openauth": "latest",
    },
  },
  "oauth-buttons": {
    name: "OAuth Buttons",
    description: "Social login buttons",
    files: ["components/OAuthButtons.tsx", "lib/auth/oauth.ts"],
    dependencies: {
      "@skoly/openauth": "latest",
    },
  },
};

export async function getComponents() {
  return components;
}
