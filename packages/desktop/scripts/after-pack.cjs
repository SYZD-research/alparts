'use strict';

const path = require('node:path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

module.exports = async function hardenPackagedElectron(context) {
  const productName = context.packager.appInfo.productFilename;
  const executableName = context.packager.executableName || productName;
  const binaryPath = context.electronPlatformName === 'darwin'
    ? path.join(context.appOutDir, `${productName}.app`, 'Contents', 'MacOS', executableName)
    : context.electronPlatformName === 'win32'
      ? path.join(context.appOutDir, `${executableName}.exe`)
      : path.join(context.appOutDir, executableName);

  await flipFuses(binaryPath, {
    version: FuseVersion.V1,
    resetAdHocDarwinSignature: context.electronPlatformName === 'darwin' && context.arch === 3,
    strictlyRequireAllFuses: true,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: context.electronPlatformName !== 'linux',
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    [FuseV1Options.WasmTrapHandlers]: true,
  });
};
