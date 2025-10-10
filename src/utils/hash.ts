import "dotenv/config";
import Debug from "debug";
import bcrypt from "bcrypt";

const debug = Debug("app:hash");

export const hashPassword = async (
  plainPassword: string,
  saltRounds: number
): Promise<string> => {
  // const salt = await bcrypt.genSalt(saltRounds);
  // const hashedPassword = await bcrypt.hash(plainPassword, salt);

  const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);

  return hashedPassword;
};
