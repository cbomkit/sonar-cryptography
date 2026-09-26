'use strict';

/**
 * Inventory runner for Node.js crypto/tls APIs.
 *
 * Uses ESLint's Linter (espree) to parse JavaScript and walk the AST. This is
 * not a regex scanner: string/comment/template nesting is handled by the parser,
 * and calls are emitted only when the receiver is a crypto/tls module, a
 * destructured import, or a tracked instance (e.g. crypto.Hash).
 */

const { Linter } = require('eslint');

const FACTORY_RESULT_TYPES = {
  createHash: 'crypto.Hash',
  createHmac: 'crypto.Hmac',
  createCipher: 'crypto.Cipher',
  createCipheriv: 'crypto.Cipher',
  createDecipher: 'crypto.Decipher',
  createDecipheriv: 'crypto.Decipher',
  createSign: 'crypto.Sign',
  createVerify: 'crypto.Verify',
  createDiffieHellman: 'crypto.DiffieHellman',
  createECDH: 'crypto.ECDH'
};

const CRYPTO_MODULE_METHODS = new Set([
  'createHash', 'createHmac',
  'createCipher', 'createCipheriv', 'createDecipher', 'createDecipheriv',
  'createSign', 'createVerify', 'sign', 'verify',
  'createDiffieHellman', 'createECDH',
  'createSecretKey', 'createPublicKey', 'createPrivateKey',
  'generateKey', 'generateKeySync', 'generateKeyPair', 'generateKeyPairSync',
  'pbkdf2', 'pbkdf2Sync', 'scrypt', 'scryptSync', 'hkdf', 'hkdfSync',
  'randomBytes', 'randomFill', 'randomFillSync', 'randomInt', 'randomUUID',
  'publicEncrypt', 'privateDecrypt', 'privateEncrypt', 'publicDecrypt'
]);

const TLS_MODULE_METHODS = new Set([
  'createSecureContext', 'connect', 'createServer', 'createConnection'
]);

const INSTANCE_METHODS = {
  'crypto.Hash': new Set(['update', 'digest', 'copy']),
  'crypto.Hmac': new Set(['update', 'digest']),
  'crypto.Cipher': new Set(['update', 'final', 'setAAD', 'getAuthTag']),
  'crypto.Decipher': new Set(['update', 'final', 'setAAD', 'setAuthTag']),
  'crypto.Sign': new Set(['update', 'sign']),
  'crypto.Verify': new Set(['update', 'verify']),
  'crypto.DiffieHellman': new Set(['generateKeys', 'computeSecret', 'setPublicKey', 'setPrivateKey']),
  'crypto.ECDH': new Set(['generateKeys', 'computeSecret', 'setPublicKey', 'setPrivateKey'])
};

function normalizeModule(specifier) {
  if (specifier === 'crypto' || specifier === 'node:crypto') {
    return 'crypto';
  }
  if (specifier === 'tls' || specifier === 'node:tls') {
    return 'tls';
  }
  return null;
}

function stringValue(node) {
  if (!node) {
    return null;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0] ? node.quasis[0].value.cooked : '';
  }
  return null;
}

function isRequireCall(node) {
  return node
    && node.type === 'CallExpression'
    && node.callee
    && node.callee.type === 'Identifier'
    && node.callee.name === 'require'
    && node.arguments.length > 0;
}

function locOf(node) {
  if (!node || !node.loc) {
    return { line: 0, column: 0 };
  }
  return {
    line: node.loc.start.line,
    column: node.loc.start.column
  };
}

function identifierName(node) {
  if (!node) {
    return null;
  }
  if (node.type === 'Identifier') {
    return node.name;
  }
  if (node.type === 'ThisExpression') {
    return 'this';
  }
  return null;
}

let current = null;

const linter = new Linter();
linter.defineRule('sonar-crypto-inventory', {
  meta: {
    type: 'problem',
    docs: { description: 'Collect Node.js crypto and tls API usage' },
    schema: []
  },
  create(context) {
    const state = current;

    function bindName(name, type) {
      if (name && type) {
        state.bindings[name] = type;
      }
    }

    function recordImportedFunction(localName, objectType, methodName) {
      state.importedFunctions[localName] = { objectType, methodName };
    }

    function bindRequirePattern(id, specifier) {
      const objectType = normalizeModule(specifier);
      if (!objectType) {
        return;
      }
      if (id.type === 'Identifier') {
        bindName(id.name, objectType);
        return;
      }
      if (id.type === 'ObjectPattern') {
        for (const prop of id.properties) {
          if (prop.type !== 'Property' || prop.value.type !== 'Identifier') {
            continue;
          }
          const imported = prop.key.type === 'Identifier'
            ? prop.key.name
            : (prop.key.type === 'Literal' ? String(prop.key.value) : null);
          if (imported) {
            recordImportedFunction(prop.value.name, objectType, imported);
          }
        }
      }
    }

    function recordConstant(id, init) {
      if (!id || id.type !== 'Identifier' || !init) {
        return;
      }
      const text = stringValue(init);
      if (text !== null) {
        state.variableValues[id.name] = text;
        return;
      }
      if (init.type === 'Literal' && (typeof init.value === 'number' || typeof init.value === 'boolean')) {
        state.variableValues[id.name] = String(init.value);
      }
    }

    function resolveObjectType(node) {
      if (!node) {
        return null;
      }
      if (node.type === 'Identifier') {
        return state.bindings[node.name] || null;
      }
      if (isRequireCall(node)) {
        return normalizeModule(stringValue(node.arguments[0]));
      }
      if (node.type === 'MemberExpression' && !node.computed) {
        return resolveObjectType(node.object);
      }
      return null;
    }

    function toArgument(node) {
      const loc = locOf(node);
      if (node.type === 'Literal') {
        if (typeof node.value === 'string') {
          return { kind: 'literal', type: 'string', value: node.value, ...loc };
        }
        if (typeof node.value === 'number') {
          return { kind: 'literal', type: 'number', value: String(node.value), ...loc };
        }
        if (typeof node.value === 'boolean') {
          return { kind: 'literal', type: 'boolean', value: String(node.value), ...loc };
        }
      }
      const template = stringValue(node);
      if (template !== null && node.type === 'TemplateLiteral') {
        return { kind: 'literal', type: 'string', value: template, ...loc };
      }
      if (node.type === 'Identifier') {
        return { kind: 'identifier', type: 'any', value: node.name, ...loc };
      }
      if (node.type === 'ObjectExpression') {
        const props = {};
        for (const prop of node.properties) {
          if (prop.type !== 'Property' || prop.computed) {
            continue;
          }
          const key = prop.key.type === 'Identifier'
            ? prop.key.name
            : (prop.key.type === 'Literal' ? String(prop.key.value) : null);
          if (key && prop.value.type === 'Literal') {
            props[key] = prop.value.value;
          }
        }
        return { kind: 'literal', type: 'object', value: JSON.stringify(props), ...loc };
      }
      if (node.type === 'ArrayExpression') {
        return { kind: 'literal', type: 'array', value: '', ...loc };
      }
      if (node.type === 'CallExpression') {
        const callee = describeCallee(node);
        return {
          kind: 'call',
          type: 'any',
          value: '',
          objectType: callee.objectType,
          methodName: callee.methodName,
          resultType: callee.resultType,
          ...loc
        };
      }
      if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
        return {
          kind: 'member',
          type: 'any',
          value: '',
          objectType: identifierName(node.object) || resolveObjectType(node.object) || 'unknown',
          methodName: node.property.name,
          ...loc
        };
      }
      return { kind: 'literal', type: 'any', value: '', ...loc };
    }

    function describeCallee(node) {
      const empty = { objectType: null, methodName: null, resultType: 'object' };
      if (!node || node.type !== 'CallExpression') {
        return empty;
      }
      const callee = node.callee;
      if (callee.type === 'Identifier') {
        const imported = state.importedFunctions[callee.name];
        if (imported) {
          return {
            objectType: imported.objectType,
            methodName: imported.methodName,
            resultType: FACTORY_RESULT_TYPES[imported.methodName] || 'object'
          };
        }
        return empty;
      }
      if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
        const methodName = callee.property.name;
        const objectType = resolveObjectType(callee.object);
        return {
          objectType,
          methodName,
          resultType: FACTORY_RESULT_TYPES[methodName] || (objectType && INSTANCE_METHODS[objectType] ? objectType : 'object')
        };
      }
      return empty;
    }

    function shouldEmit(objectType, methodName) {
      if (!objectType || !methodName) {
        return false;
      }
      if (objectType === 'crypto' && CRYPTO_MODULE_METHODS.has(methodName)) {
        return true;
      }
      if (objectType === 'tls' && TLS_MODULE_METHODS.has(methodName)) {
        return true;
      }
      const instance = INSTANCE_METHODS[objectType];
      return Boolean(instance && instance.has(methodName));
    }

    function variableNameForCall(node) {
      const ancestors = context.getAncestors();
      const parent = ancestors[ancestors.length - 1];
      if (parent && parent.type === 'VariableDeclarator' && parent.init === node && parent.id.type === 'Identifier') {
        return parent.id.name;
      }
      if (parent && parent.type === 'AssignmentExpression' && parent.right === node && parent.left.type === 'Identifier') {
        return parent.left.name;
      }
      return null;
    }

    function emitCall(node) {
      const described = describeCallee(node);
      if (!shouldEmit(described.objectType, described.methodName)) {
        return;
      }
      const variableName = variableNameForCall(node);
      const resultType = FACTORY_RESULT_TYPES[described.methodName] || described.resultType || 'object';
      if (variableName && FACTORY_RESULT_TYPES[described.methodName]) {
        bindName(variableName, resultType);
      }
      const loc = locOf(node);
      state.calls.push({
        kind: 'call',
        methodName: described.methodName,
        objectType: described.objectType,
        resultType,
        variableName,
        line: loc.line,
        column: loc.column,
        arguments: node.arguments.map(toArgument)
      });
    }

    return {
      ImportDeclaration(node) {
        const objectType = normalizeModule(stringValue(node.source));
        if (!objectType) {
          return;
        }
        for (const spec of node.specifiers) {
          if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
            bindName(spec.local.name, objectType);
          } else if (spec.type === 'ImportSpecifier') {
            const imported = spec.imported.type === 'Identifier' ? spec.imported.name : null;
            if (imported) {
              recordImportedFunction(spec.local.name, objectType, imported);
            }
          }
        }
      },
      VariableDeclarator(node) {
        recordConstant(node.id, node.init);
        if (node.init && isRequireCall(node.init)) {
          bindRequirePattern(node.id, stringValue(node.init.arguments[0]));
        }
      },
      AssignmentExpression(node) {
        if (node.left.type === 'Identifier') {
          recordConstant(node.left, node.right);
          if (isRequireCall(node.right)) {
            bindRequirePattern(node.left, stringValue(node.right.arguments[0]));
          }
        }
      },
      CallExpression(node) {
        emitCall(node);
      }
    };
  }
});

function analyzeFile(file) {
  current = {
    bindings: {},
    variableValues: {},
    importedFunctions: {},
    calls: []
  };
  const content = file.content || '';
  const messages = linter.verify(
    content,
    {
      env: { es2022: true, node: true },
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        ecmaFeatures: { jsx: true }
      },
      rules: { 'sonar-crypto-inventory': 'error' }
    },
    { filename: file.path || 'file.js' }
  );
  const fatal = messages.find((message) => message.fatal);
  if (fatal) {
    return {
      path: file.path,
      parseError: fatal.message
    };
  }
  return {
    path: file.path,
    bindings: current.bindings,
    variableValues: current.variableValues,
    calls: current.calls
  };
}

let input = '';
process.stdin.on('data', (chunk) => {
  input += chunk;
});
process.stdin.on('end', () => {
  try {
    const request = JSON.parse(input);
    const results = [];
    for (const file of request.files || []) {
      try {
        results.push(analyzeFile(file));
      } catch (err) {
        results.push({
          path: file.path,
          parseError: err.message
        });
      }
    }
    console.log(JSON.stringify({ files: results }));
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
});
