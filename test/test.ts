import { OgnaClient } from "../src";

function generateRandomEmail(): string {
  const firstNames = [
    "john",
    "jane",
    "alex",
    "sarah",
    "mike",
    "emma",
    "david",
    "lisa",
  ];
  const lastNames = [
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "garcia",
    "miller",
    "davis",
  ];
  const domains = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "example.com",
  ];

  const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
  const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
  const domain = domains[Math.floor(Math.random() * domains.length)];

  // Random number between 0-999
  const randomNum = Math.floor(Math.random() * 1000);

  // Randomly choose email format
  const formats = [
    `${firstName}.${lastName}@${domain}`,
    `${firstName}${lastName}@${domain}`,
    `${firstName}.${lastName}${randomNum}@${domain}`,
    `${firstName}${randomNum}@${domain}`,
  ];

  const format = formats[Math.floor(Math.random() * formats.length)];

  return format;
}

async function main() {
  const auth = new OgnaClient("http://localhost:8000");

  const email = generateRandomEmail();
  const password = "password123";

  const signup = await auth.signup(email, password);
  console.log("Signup:", signup);

  const login = await auth.login(email, password, true);
  console.log("Login:", login);

  const { data, error } = await auth.get("/v1/check/");
  if (error) {
    console.error("API error:", error);
  } else {
    console.log("Todos:", data);
  }

  const refresh = await auth.refreshSession();
  console.log("refresh:", refresh);

  const fetch2 = await auth.get("/v1/check/");
  if (fetch2.error) {
    console.error("API error:", error);
  } else {
    console.log("Todos:", fetch2.data);
  }

  const logout = await auth.logout();
  console.log("logout:", logout);
}

main().catch(console.error);
