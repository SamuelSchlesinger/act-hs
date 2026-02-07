import Distribution.Simple
import Distribution.Simple.LocalBuildInfo (LocalBuildInfo, localPkgDescr)
import Distribution.Simple.Setup (BuildFlags, ConfigFlags)
import Distribution.Types.BuildInfo (BuildInfo, extraLibDirs)
import Distribution.Types.GenericPackageDescription (GenericPackageDescription)
import Distribution.Types.HookedBuildInfo (HookedBuildInfo, emptyHookedBuildInfo)
import Distribution.Types.Library (Library, libBuildInfo)
import Distribution.Types.PackageDescription (PackageDescription, library)
import System.Directory (getCurrentDirectory)
import System.Process (callProcess)

main :: IO ()
main = defaultMainWithHooks simpleUserHooks
  { confHook = rustConfHook
  , preBuild = rustPreBuild
  }

rustBuild :: IO ()
rustBuild = do
  cwd <- getCurrentDirectory
  let manifestPath = cwd ++ "/ffi/Cargo.toml"
  callProcess "cargo" ["build", "--release", "--manifest-path", manifestPath]

rustPreBuild :: Args -> BuildFlags -> IO HookedBuildInfo
rustPreBuild _ _ = do
  rustBuild
  return emptyHookedBuildInfo

rustConfHook :: (GenericPackageDescription, HookedBuildInfo) -> ConfigFlags -> IO LocalBuildInfo
rustConfHook (gpd, hbi) flags = do
  rustBuild

  -- Run the default configure
  lbi <- confHook simpleUserHooks (gpd, hbi) flags

  -- Inject the absolute path to the Rust static library
  cwd <- getCurrentDirectory
  let libDir = cwd ++ "/ffi/target/release"
      updateBI :: BuildInfo -> BuildInfo
      updateBI bi = bi { extraLibDirs = libDir : extraLibDirs bi }
      updateLib :: Library -> Library
      updateLib lib = lib { libBuildInfo = updateBI (libBuildInfo lib) }
      updatePkgDesc :: PackageDescription -> PackageDescription
      updatePkgDesc pd = pd { library = fmap updateLib (library pd) }
  return lbi { localPkgDescr = updatePkgDesc (localPkgDescr lbi) }
