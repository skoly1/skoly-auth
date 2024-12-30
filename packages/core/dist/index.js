"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  Auth: () => Auth
});
module.exports = __toCommonJS(index_exports);
var Auth = class {
  constructor(config) {
    this.config = {
      tokenExpiry: 60 * 60 * 24,
      // 24 hours
      secureCookies: true,
      ...config
    };
  }
  async init() {
    return {
      success: true
    };
  }
  // We'll expand these methods as we build the system
  async createUser(email, password) {
    return {
      success: true
    };
  }
  async verifyUser(email, password) {
    return {
      success: true
    };
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  Auth
});
