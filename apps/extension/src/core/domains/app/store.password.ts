import { StorageProvider } from "@core/libs/Store"
import { sessionStorage } from "@core/util/sessionStorageCompat"
import { assert } from "@polkadot/util"
import { genSalt, hash } from "bcryptjs"
import { BehaviorSubject } from "rxjs"
import { Err, Ok, Result } from "ts-results"

/* ----------------------------------------------------------------
Contains sensitive data.
Should not be used outside of the Extension handler.
------------------------------------------------------------------*/

type LOGGEDIN_TRUE = "TRUE"
type LOGGEDIN_FALSE = "FALSE"
type LOGGEDIN_UNKNOWN = "UNKNOWN"
const TRUE: LOGGEDIN_TRUE = "TRUE"
const FALSE: LOGGEDIN_FALSE = "FALSE"
const UNKNOWN: LOGGEDIN_UNKNOWN = "UNKNOWN"

export type LoggedInType = LOGGEDIN_TRUE | LOGGEDIN_FALSE | LOGGEDIN_UNKNOWN

export type PasswordStoreData = {
  salt?: string
  isTrimmed: boolean
  isHashed: boolean
  ignorePasswordUpdate: boolean
}

const initialData = {
  // passwords from early versions of Talisman were 'trimmed'.
  isTrimmed: true,
  isHashed: false,
  salt: undefined,
  ignorePasswordUpdate: false,
}

export class PasswordStore extends StorageProvider<PasswordStoreData> {
  isLoggedIn = new BehaviorSubject<LoggedInType>(UNKNOWN)
  #autoLockTimer?: NodeJS.Timeout

  constructor(prefix: string, data: Partial<PasswordStoreData> = initialData) {
    super(prefix, data)
    // on every instantiation of this store, check to see if logged in
    this.hasPassword().then((result) => {
      this.isLoggedIn.next(result ? TRUE : FALSE)
    })
  }

  public resetAutoLockTimer(seconds: number) {
    if (this.#autoLockTimer) clearTimeout(this.#autoLockTimer)
    if (seconds > 0) this.#autoLockTimer = setTimeout(() => this.clearPassword(), seconds * 1000)
  }

  async reset() {
    // use with caution
    return this.set({
      isTrimmed: false,
      isHashed: true,
      salt: undefined,
      ignorePasswordUpdate: false,
    })
  }

  async createPassword(plaintextPw: string) {
    const salt = await generateSalt()
    const { err, val } = await getHashedPassword(plaintextPw, salt)
    if (err) throw new Error(val)
    return { password: val, salt }
  }

  setPassword(password: string | undefined) {
    sessionStorage.set({ password })
    this.isLoggedIn.next(password !== undefined ? TRUE : FALSE)
  }

  public async getHashedPassword(plaintextPw: string) {
    const salt = await this.get("salt")
    assert(salt, "Password salt has not been generated yet")
    const { err, val } = await getHashedPassword(plaintextPw, salt)
    if (err) throw new Error(val)
    return val
  }

  public async setPlaintextPassword(plaintextPw: string) {
    const pw = await this.transformPassword(plaintextPw)
    this.setPassword(pw)
  }

  public clearPassword() {
    this.setPassword(undefined)
  }

  async transformPassword(password: string) {
    let result = password
    const { isTrimmed, isHashed, salt } = await this.get()
    if (isTrimmed) result = result.trim()
    if (isHashed) {
      assert(salt, "Password salt has not been generated yet")
      const { ok, val: hashedPwVal } = await getHashedPassword(result, salt)
      if (!ok) throw new Error(hashedPwVal)
      result = hashedPwVal
    }
    return result
  }

  async checkPassword(password: string) {
    assert(this.isLoggedIn.value, "Unauthorised")
    const pw = await this.transformPassword(password)
    assert(pw === (await this.getPassword()), "Incorrect password")
    return pw
  }

  async getPassword() {
    const pw = await sessionStorage.get("password")
    if (!pw) return undefined
    return pw
  }

  async hasPassword() {
    return !!(await sessionStorage.get("password"))
  }
}

export const generateSalt = () => genSalt(13)

export const getHashedPassword = async (
  password: string,
  salt: string
): Promise<Result<string, string>> => {
  try {
    const derivedHash = await hash(password, salt)
    return Ok(derivedHash)
  } catch (error) {
    return Err(error as string)
  }
}

const passwordStore = new PasswordStore("password")
export default passwordStore
