const fs = require('fs');
const path = require('path');

async function updateDependencies() {
    const packagesDir = path.join(__dirname, '..', 'packages');
    const packageDirs = fs.readdirSync(packagesDir).filter(dir =>
        fs.statSync(path.join(packagesDir, dir)).isDirectory() &&
        fs.existsSync(path.join(packagesDir, dir, 'package.json'))
    );

    const packageVersions = {};
    for (const dir of packageDirs) {
        const packageJsonPath = path.join(packagesDir, dir, 'package.json');
        const packageJson = require(packageJsonPath);
        packageVersions[packageJson.name] = packageJson.version;
    }

    for (const dir of packageDirs) {
        const packageJsonPath = path.join(packagesDir, dir, 'package.json');
        const packageJson = require(packageJsonPath);
        let updated = false;

        if (packageJson.dependencies) {
            for (const dep in packageJson.dependencies) {
                if (packageJson.dependencies[dep] === 'workspace:*' && packageVersions[dep]) {
                    packageJson.dependencies[dep] = packageVersions[dep];
                    updated = true;
                }
            }
        }
        if (packageJson.devDependencies) {
            for (const dep in packageJson.devDependencies) {
                if (packageJson.devDependencies[dep] === 'workspace:*' && packageVersions[dep]) {
                    packageJson.devDependencies[dep] = packageVersions[dep];
                    updated = true;
                }
            }
        }
        if (packageJson.peerDependencies) {
            for (const dep in packageJson.peerDependencies) {
                if (packageJson.peerDependencies[dep] === 'workspace:*' && packageVersions[dep]) {
                    packageJson.peerDependencies[dep] = packageVersions[dep];
                    updated = true;
                }
            }
        }

        if (updated) {
            fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
            console.log(`Updated dependencies in ${packageJsonPath}`);
        }
    }
}

updateDependencies().catch(err => {
    console.error('Error updating dependencies:', err);
    process.exit(1);
});