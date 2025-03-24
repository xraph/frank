#!/bin/bash
set -e

# Frank Authentication Server Generate Script

echo "🔧 Generating code for Frank Authentication Server..."

# Go to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

# Check if ent CLI is installed
if ! command -v ent &> /dev/null; then
    echo "❌ ent CLI is not installed. Please run setup.sh first."
    exit 1
fi

# Generate Ent code
echo "🧩 Generating Ent code..."
go generate ./ent

# Install protoc and plugins if needed
if ! command -v protoc &> /dev/null; then
    echo "⚠️ protoc not found. Installing protobuf tooling..."

    # Check OS
    OS=$(uname -s)
    ARCH=$(uname -m)

    if [ "$OS" = "Linux" ]; then
        echo "🐧 Linux detected..."
        PROTOC_ZIP="protoc-24.4-linux-x86_64.zip"
        curl -OL "https://github.com/protocolbuffers/protobuf/releases/download/v24.4/$PROTOC_ZIP"
        sudo unzip -o $PROTOC_ZIP -d /usr/local bin/protoc
        sudo unzip -o $PROTOC_ZIP -d /usr/local 'include/*'
        rm -f $PROTOC_ZIP
    elif [ "$OS" = "Darwin" ]; then
        echo "🍎 macOS detected..."
        brew install protobuf
    else
        echo "❌ Unsupported OS for automatic protoc installation. Please install manually."
        exit 1
    fi

    # Install Go plugins for protoc
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Check and install OpenAPI Generator if needed (for Go client)
if ! command -v openapi-generator &> /dev/null; then
    echo "⚠️ openapi-generator not found. Installing OpenAPI Generator..."

    # Check OS
    OS=$(uname -s)

    if [ "$OS" = "Linux" ]; then
        echo "🐧 Linux detected..."
        # Check if npm is available
        if command -v npm &> /dev/null; then
            npm install @openapitools/openapi-generator-cli -g
        else
            # Manual installation using Java
            if command -v java &> /dev/null; then
                echo "Installing via JAR download..."
                mkdir -p "$HOME/bin"
                curl -L "https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/6.6.0/openapi-generator-cli-6.6.0.jar" -o "$HOME/bin/openapi-generator-cli.jar"
                echo '#!/bin/bash' > "$HOME/bin/openapi-generator"
                echo 'java -jar "'$HOME'/bin/openapi-generator-cli.jar" "$@"' >> "$HOME/bin/openapi-generator"
                chmod +x "$HOME/bin/openapi-generator"
                export PATH="$HOME/bin:$PATH"
                echo "Please add $HOME/bin to your PATH permanently in your shell profile."
            else
                echo "❌ Java not found. Please install Java and OpenAPI Generator manually."
                echo "You can download OpenAPI Generator from https://github.com/OpenAPITools/openapi-generator"
            fi
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo "🍎 macOS detected..."
        brew install openapi-generator
    else
        echo "❌ Unsupported OS for automatic OpenAPI Generator installation. Please install manually."
        echo "You can download OpenAPI Generator from https://github.com/OpenAPITools/openapi-generator"
    fi

    # Verify installation
    if ! command -v openapi-generator &> /dev/null; then
        echo "⚠️ OpenAPI Generator installation may have failed. Continuing without it."
        echo "Please install manually from https://github.com/OpenAPITools/openapi-generator"
    else
        echo "✅ OpenAPI Generator installed successfully!"
    fi
fi

# Generate protocol buffers
echo "📄 Generating protocol buffer code..."
mkdir -p internal/pb

# Generate each proto file
for proto_file in api/proto/*.proto; do
    echo "Processing $proto_file..."
    protoc --proto_path=api/proto \
           --go_out=internal/pb --go_opt=paths=source_relative \
           --go-grpc_out=internal/pb --go-grpc_opt=paths=source_relative \
           "$proto_file"
done

# Generate OpenAPI Go client code
if command -v openapi-generator &> /dev/null; then
    echo "📚 Generating OpenAPI GO client code..."
    echo "⚠️ openapi-generator found. Skipping OpenAPI Go client generation."
#    openapi-generator generate -i gen/http/openapi3.json -g go -o client \
#        --package-name client \
#        --skip-validate-spec \
#        --additional-properties=removeOperationIdPrefix=true,usePromises=true,returnExceptionBody=true
else
    echo "⚠️ openapi-generator not found. Skipping OpenAPI Go client generation."
fi

# Generate TypeScript client using Orval
echo "📚 Generating TypeScript client using Orval..."

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Please install Node.js and npm to use Orval."
    echo "Skipping TypeScript client generation."
else
    # Check if Orval is installed
#    if ! npm list -g | grep -q orval; then
#        echo "⚠️ Orval not found. Installing Orval..."
#        pnpm install -g orval
#    fi

    # Create Orval config file
    echo "Creating Orval configuration..."
    mkdir -p web/js-sdk

    cat > orval.config.js << EOF
module.exports = {
  frankClient: {
    input: {
      target: './gen/http/openapi3.json',
    },
    output: {
      mode: 'tags-split',
      target: './web/js-sdk/src',
      schemas: './web/js-sdk/src/model',
      client: 'react-query',
      mock: true,
      override: {
        mutator: {
          path: './web/js-sdk/src/api/mutator/custom-instance.ts',
          name: 'customInstance',
        },
        operations: {},
        query: {
          useQuery: true,
          useInfinite: true,
          useInfiniteQueryParam: 'pageParam',
          useMutation: true,
        },
      },
      prettier: true,
      clean: true,
    },
  },
};
EOF

    # Create custom instance file for fetching
    mkdir -p web/js-sdk/src/api/mutator
    cat > web/js-sdk/src/api/mutator/custom-instance.ts << EOF
import axios from 'axios';

export const customInstance = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

export default customInstance;
EOF

    # Create package.json for the JS SDK
    cat > web/js-sdk/package.json << EOF
{
  "name": "frank-client",
  "version": "1.0.0",
  "description": "Frank Authentication TypeScript Client",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "generate": "orval"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "react-query": "^3.39.3"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "orval": "^6.17.0",
    "@types/node": "^20.0.0",
    "@types/react": "^18.0.0"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  }
}
EOF

    # Create tsconfig.json for the JS SDK
    cat > web/js-sdk/tsconfig.json << EOF
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "declaration": true,
    "outDir": "./dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
EOF

    # Create index.ts file to export all generated APIs
    cat > web/js-sdk/src/index.ts << EOF
// This file will be populated with exports from generated API clients
export * from './api/mutator/custom-instance';
// NOTE: After generation, you'll need to add exports for all generated APIs
EOF

    # Run Orval to generate the TypeScript client
    echo "Running Orval to generate TypeScript client..."
    npx orval --config ./orval.config.js

    echo "✅ TypeScript client generation with Orval complete!"

    # Add README to explain how to use the generated client
    cat > web/js-sdk/README.md << EOF
# Frank Authentication TypeScript Client

This TypeScript client for the Frank Authentication Server is generated using Orval.

## Installation

\`\`\`
npm install frank-client
\`\`\`

## Usage

\`\`\`typescript
import { useLogin, useGetUser } from 'frank-client';
import { customInstance } from 'frank-client';

// Configure the client
customInstance.defaults.baseURL = 'https://your-frank-server.com/api';

// Set auth token
const setAuthToken = (token) => {
  customInstance.defaults.headers.common['Authorization'] = \`Bearer \${token}\`;
};

// Use the generated hooks
function MyComponent() {
  const { mutate: login } = useLogin();
  const { data: user } = useGetUser();

  const handleLogin = () => {
    login({
      email: 'user@example.com',
      password: 'password123'
    }, {
      onSuccess: (data) => {
        setAuthToken(data.token);
      }
    });
  };

  return (
    <div>
      {user ? <p>Welcome, {user.name}</p> : <button onClick={handleLogin}>Login</button>}
    </div>
  );
}
\`\`\`
EOF
fi

# Generate mock files for testing
echo "🧪 Generating mocks for testing..."
go install github.com/golang/mock/mockgen@latest

# List of interfaces to mock
INTERFACES_TO_MOCK=(
    "internal/user.Service"
    "internal/auth/session.Store"
    "internal/auth/oauth2.Storage"
    "internal/organization.Service"
    "internal/webhook.Service"
    "internal/auth/mfa.Service"
    "internal/auth/passkeys.Service"
    "internal/auth/passwordless.Service"
    "internal/auth/sso.Service"
    "internal/apikeys.Service"

    "internal/apikeys.Repository"
    "internal/user.Repository"
    "internal/auth/session.Store"
    "internal/organization.Repository"
    "internal/webhook.Repository"
    "internal/auth/passkeys.Repository"
    "internal/email.TemplateRepository"
)

# Generate mocks
mkdir -p internal/mocks
for interface in "${INTERFACES_TO_MOCK[@]}"; do
    # Extract package and interface name
    PKG=$(echo $interface | cut -d. -f1)
    INTF=$(echo $interface | cut -d. -f2)

    # Extract the actual package name (last component of the path)
    PKG_NAME=$(basename $PKG)

    # Capitalize first letter of package name using tr (more compatible than ^ operator)
    PKG_NAME_CAP=$(echo $PKG_NAME | tr '[:lower:]' '[:upper:]' | cut -c1)$(echo $PKG_NAME | cut -c2-)

    echo "Generating mock for $INTF with mock name Mock${PKG_NAME_CAP}${INTF}..."

    # Generate mocks with mock name prefixed by package name
    mockgen -destination tests/mocks/${PKG_NAME_CAP}${INTF}_mock.go -package mocks -mock_names "${INTF}=Mock${PKG_NAME_CAP}${INTF}" github.com/juicycleff/frank/$PKG $INTF
done

echo "✅ Code generation complete!"