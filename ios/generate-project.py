#!/usr/bin/env python3
"""Generate the checked-in Xcode project without a third-party generator."""
from pathlib import Path
import hashlib
root = Path(__file__).resolve().parent
objects = {}
def ident(value): return hashlib.sha256(value.encode()).hexdigest()[:24].upper()
def obj(name, value):
    key = ident(name); objects[key] = value; return key
files = []
for file in sorted((root / 'AgentCreds').glob('*.swift')):
    ref = obj(str(file.name), f'{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = AgentCreds/{file.name}; sourceTree = "<group>"; }}')
    files.append(obj('build'+file.name, f'{{isa = PBXBuildFile; fileRef = {ref}; }}'))
product = obj('product', '{isa = PBXFileReference; explicitFileType = wrapper.application; path = AgentCreds.app; sourceTree = BUILT_PRODUCTS_DIR; }')
package = obj('package', '{isa = XCLocalSwiftPackageReference; relativePath = ..; }')
packageProduct = obj('packageproduct', f'{{isa = XCSwiftPackageProductDependency; package = {package}; productName = CompanionProtocol; }}')
framework = obj('framework', f'{{isa = PBXBuildFile; productRef = {packageProduct}; }}')
sources = obj('sources', '{isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ('+','.join(files)+'); runOnlyForDeploymentPostprocessing = 0; }')
frameworks = obj('frameworks', f'{{isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({framework}); runOnlyForDeploymentPostprocessing = 0; }}')
assetRef = obj('assets', '{isa = PBXFileReference; lastKnownFileType = folder.assetcatalog; path = AgentCreds/Assets.xcassets; sourceTree = "<group>"; }')
assetBuild = obj('assetbuild', f'{{isa = PBXBuildFile; fileRef = {assetRef}; }}')
resources = obj('resources', '{isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ('+assetBuild+'); runOnlyForDeploymentPostprocessing = 0; }')
configs=[]; projectConfigs=[]
for name in ['Debug','Release']:
    settings='ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon; CODE_SIGN_STYLE = Automatic; CODE_SIGN_ENTITLEMENTS = AgentCreds/AgentCreds.entitlements; INFOPLIST_FILE = AgentCreds/Info.plist; PRODUCT_BUNDLE_IDENTIFIER = ai.ardabot.agentcreds.companion; PRODUCT_NAME = "$(TARGET_NAME)"; SWIFT_VERSION = 5.0; TARGETED_DEVICE_FAMILY = "1,2"; IPHONEOS_DEPLOYMENT_TARGET = 17.0; SDKROOT = iphoneos; SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; GENERATE_INFOPLIST_FILE = NO;'
    settings += ' ONLY_ACTIVE_ARCH = YES; SWIFT_OPTIMIZATION_LEVEL = "-Onone"; SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;' if name=='Debug' else ' SWIFT_OPTIMIZATION_LEVEL = "-O";'
    settings += ' APNS_ENVIRONMENT = ' + ('development' if name == 'Debug' else 'production') + ';'
    configs.append(obj('app'+name, f'{{isa = XCBuildConfiguration; name = {name}; buildSettings = {{{settings}}}; }}'))
    projectConfigs.append(obj('project'+name, f'{{isa = XCBuildConfiguration; name = {name}; buildSettings = {{CLANG_ENABLE_MODULES = YES; }}; }}'))
appConfig=obj('appconfig','{isa = XCConfigurationList; buildConfigurations = ('+','.join(configs)+'); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }')
projectConfig=obj('projectconfig','{isa = XCConfigurationList; buildConfigurations = ('+','.join(projectConfigs)+'); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release; }')
products=obj('products',f'{{isa = PBXGroup; children = ({product}); name = Products; sourceTree = "<group>"; }}')
refs=[ident(f.name) for f in sorted((root/'AgentCreds').glob('*.swift'))]+[assetRef,products]
group=obj('group','{isa = PBXGroup; children = ('+','.join(refs)+'); sourceTree = "<group>"; }')
target=obj('target',f'{{isa = PBXNativeTarget; buildConfigurationList = {appConfig}; buildPhases = ({sources},{frameworks},{resources}); buildRules = (); dependencies = (); name = AgentCreds; packageProductDependencies = ({packageProduct}); productName = AgentCreds; productReference = {product}; productType = "com.apple.product-type.application"; }}')
project=obj('project',f'{{isa = PBXProject; attributes = {{LastUpgradeCheck = 2600; }}; buildConfigurationList = {projectConfig}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en,Base); mainGroup = {group}; productRefGroup = {products}; projectDirPath = ""; projectRoot = ""; packageReferences = ({package}); targets = ({target}); }}')
out=root/'AgentCreds.xcodeproj'; out.mkdir(exist_ok=True)
(out/'project.pbxproj').write_text('// !$*UTF8*$!\n{archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n'+'\n'.join(k+' = '+v+';' for k,v in objects.items())+'\n}; rootObject = '+project+'; }\n')
scheme=out/'xcshareddata/xcschemes'; scheme.mkdir(parents=True,exist_ok=True)
(scheme/'AgentCreds.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2600" version="1.3"><BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{target}" BuildableName="AgentCreds.app" BlueprintName="AgentCreds" ReferencedContainer="container:AgentCreds.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction><LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{target}" BuildableName="AgentCreds.app" BlueprintName="AgentCreds" ReferencedContainer="container:AgentCreds.xcodeproj"/></BuildableProductRunnable></LaunchAction><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/></Scheme>''')
print(out)
