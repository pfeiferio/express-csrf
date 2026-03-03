declare module "express-serve-static-core" {
  interface Request {
    csrf: {
      hasSecret(): boolean
      generateToken(): string | false
      isExcluded(): boolean
      isTokenCreationSkipped(): boolean
      isValidationSkipped(): boolean
    }
  }

  interface Locals {
    csrfToken?: string
  }
}

export {};
