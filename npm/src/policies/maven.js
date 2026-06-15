/**
 * Java / Maven / Gradle ecosystem policy.
 *
 * Hardened profile for running Java build tools. Covers:
 * - Maven Central hosts
 * - Gradle hosts
 * - JDK path detection
 * - SSL certificate paths
 * - Build directory isolation
 * - Cache directory isolation
 *
 * @module policies/maven
 */

import { join } from 'node:path';
import { getSslPaths, isMac } from './sslhelper.js';

function resolveJdkPath() {
  if (process.env.JAVA_HOME) {
    return process.env.JAVA_HOME;
  }
  if (isMac) {
    return '/Library/Java/JavaVirtualMachines';
  }
  return '/usr/lib/jvm';
}

export function mavenPolicy() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const jdkPath = resolveJdkPath();

  return {
    allowHosts: [
      'repo.maven.apache.org',
      'repo1.maven.org',
      'services.gradle.org',
      'jcenter.bintray.com', // Note: JCenter is sunsetting, consider dropping if not legacy
      'plugins.gradle.org',
    ],

    readPaths: [
      jdkPath,
      ...getSslPaths(),
      join(cwd, 'pom.xml'),
      join(cwd, 'build.gradle'),
      join(cwd, 'build.gradle.kts'),
      join(cwd, 'settings.gradle'),
      join(cwd, 'settings.gradle.kts'),
      join(cwd, 'gradlew'),
      join(cwd, 'mvnw'),
    ],

    writePaths: [
      join(cwd, 'target'),
      join(cwd, 'build'),
      join(cwd, '.gradle'),
      join(home, '.m2'),
      join(home, '.gradle'),
    ],

    env: {
      MAVEN_OPTS: '-Xmx512m',
      // CRITICAL: Disable the background daemon which frequently escapes sandboxing
      // or causes processes to hang forever inside isolated containers.
      GRADLE_OPTS: '-Xmx512m -Dorg.gradle.daemon=false -Dorg.gradle.welcome=never',
    },

    /** OS-level blocking to prevent malicious maven-antrun-plugin or shell tasks */
    blockFork: true,
    denyPersistenceWrites: true,
    blockInterpreters: true,
    blockExec: ['*'],
  };
}

export default mavenPolicy;