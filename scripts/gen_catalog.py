#!/usr/bin/env python3
"""Generate the long-tail Backend API / Platform API surface of the `atlas-auth`
gem from the public OpenAPI document.

Usage (from sdks/ruby):

    python3 scripts/gen_catalog.py                # from scripts/openapi.snapshot.json
    python3 scripts/gen_catalog.py --spec FILE    # or a local copy
    python3 scripts/gen_catalog.py --report       # also print counts
    python3 scripts/gen_catalog.py --pin          # freeze the current method names into catalog_pins.json

Reproducible: CI regenerates from the checked-in snapshot and fails on any diff.
To pick up API changes, copy a fresh snapshot into scripts/openapi.snapshot.json,
regenerate, and review the diff: additions are fine.

Writes (never edit by hand):

  lib/atlas/generated/models.rb    response models (Atlas::Models::*) with typed accessors, and
                                   Atlas::Models::OPERATIONS: operation -> model, so a hand-written
                                   call's Hash can be wrapped with Atlas::Models.wrap
  lib/atlas/generated/catalog.rb   one module per resource group with one keyword-argument method
                                   per operation the hand-written resources do not implement
  lib/atlas/generated/requests.rb  body and query fields of the operations the hand-written resources
                                   implement (Atlas::Requests.body / .query build a checked request Hash)
  test/generated/catalog_test.rb   every generated operation hits its method and path

Which operations: every BAPI + PLATFORM operation of the spec whose path (and, where it can be
told, HTTP method) the hand-written files in lib/ do not already contain.

Pinned signatures (scripts/catalog_pins.json):
  names: "METHOD /path" -> method name. A published method name never moves when the spec grows;
         new operations need no pin. A pin the spec no longer reaches is reported and ignored.
  generate_despite_handwritten: "METHOD /path" keys generated although a hand-written helper
         shares the route.

Mapping:
  path parameter         positional argument (snake_case)
  query parameter        keyword argument, omitted when not given
  JSON body property     keyword argument (required ones are required keywords); a body with
                         no declared properties (or a oneOf) is one positional Hash instead
  Idempotency-Key        `idempotency_key:` on the operations whose spec declares it
  list response          Atlas::Generated::Page: Enumerable, walks every page on #each
  object response        Atlas::Models::<Name> with typed accessors (unknown keys stay in #to_h)
"""
import json, os, re, sys, glob, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, 'lib')
GEN_DIR = os.path.join(LIB, 'atlas', 'generated')
METHODS = ('get', 'post', 'put', 'patch', 'delete')


def arg(flag):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else None


spec_file = arg('--spec') or os.path.join(HERE, 'openapi.snapshot.json')
with open(spec_file) as f:
    D = json.load(f)
COMPS = D['components']
SCHEMAS = COMPS.get('schemas', {})
PARAMS = COMPS.get('parameters', {})
with open(os.path.join(HERE, 'catalog_pins.json')) as f:
    PINS = json.load(f)

RUBY_KW = set('alias and begin break case class def defined? do else elsif end ensure false for if in module next nil not or redo rescue retry return self super then true undef unless until when while yield __FILE__ __LINE__ __method__ __dir__'.split())
# Methods every object has: a generated method or accessor must not shadow these.
RUBY_OBJ = set('dig raw hash class send method methods display freeze dup clone object_id inspect to_s to_a to_h extend instance_of? kind_of? is_a? nil? tap then itself then frozen? instance_variable_get instance_variable_set public_send respond_to? format open select test sleep puts print p raise loop lambda proc require load exit abort fork system exec trap catch throw binding caller rand srand gets sprintf printf putc warn eval at_exit autoload'.split())


def snake(s):
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s)
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s)
    s = re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_').lower()
    return s


def camel(s):
    return ''.join(p[:1].upper() + p[1:] for p in re.split(r'[^A-Za-z0-9]+', snake(s)) if p)


def safe_ident(s):
    """snake_case local name for a JSON key, or None when it cannot be one."""
    n = snake(s)
    if not re.fullmatch(r'[a-z][a-z0-9_]*', n or ''):
        return None
    return n + '_' if n in RUBY_KW else n


def sing(w):
    if w.endswith('ies'):
        return w[:-3] + 'y'
    if re.search(r'(sses|xes|ches|shes|uses)$', w):
        return w[:-2]
    if w.endswith(('ss', 'us', 'is')):
        return w
    return w[:-1] if w.endswith('s') else w


def rq(s):
    """Ruby double-quoted string literal."""
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('#', '\\#') + '"'


def deref(node):
    seen = 0
    while isinstance(node, dict) and '$ref' in node and seen < 20:
        ref = node['$ref'].split('/')
        node = (SCHEMAS if ref[-2] == 'schemas' else PARAMS if ref[-2] == 'parameters' else {}).get(ref[-1], {})
        seen += 1
    return node if isinstance(node, dict) else {}


# ── which operations ─────────────────────────────────────────────────────────
def canon(p):
    return re.sub(r'/+$', '', re.sub(r'\{[^}]*\}|\*', '{}', p))


ops = []
for p, item in D['paths'].items():
    for m in METHODS:
        o = item.get(m)
        if o and o.get('tags', [''])[0] in ('BAPI', 'PLATFORM'):
            ops.append((m, p, o))
ops.sort(key=lambda x: (x[1], METHODS.index(x[0])))


def hand_text():
    out = []
    for f in sorted(glob.glob(os.path.join(LIB, '**', '*.rb'), recursive=True)):
        if os.sep + 'generated' + os.sep in f:
            continue
        out.append(open(f).read())
    return '\n'.join(out)


HAND = hand_text()


def text_paths(t):
    t = re.sub(r'(["\'`])\s*(?:\+|\.|<>)\s*[^"\'`\n]{1,120}?\s*(?:\+|\.|<>)\s*\1', '{}', t)
    t = re.sub(r'(/v1/[\w\-./]*/)(["\'`])\s*(?:\+|\.|<>)\s*[\w$.()\[\]]+', r'\1{}\2', t)
    t = re.sub(r'(?:#|\$)?\{\{?[^{}"\'`\n]{0,120}\}?\}', '{}', t)
    out = collections.Counter()
    for m in re.finditer(r'/v1/[A-Za-z0-9_\-./{}:~]*', t):
        q = m.group(0).rstrip('.')
        if q.endswith('/'):
            q += '{}'
        out[canon(re.sub(r':[A-Za-z_]\w*', '{}', q))] += 1
    return out


# Hand-written verb+path pairs: `method: :get, path: "/v1/..."`. Every other mention of a path (a helper that builds
# the call, a dynamic verb) cannot be read as a verb, so it counts as present for every verb.
PAIR_RE = re.compile(r'method:\s*:(\w+),\s*path:\s*"(/v1/[^"]*)"')
PAIRS = set()
for m in PAIR_RE.finditer(HAND):
    PAIRS.add((m.group(1).lower(), canon(re.sub(r'#\{[^}]*\}', '{}', m.group(2)).split('?')[0])))
HAND_PATHS = text_paths(HAND)                       # what the path-only drift gate sees
UNTAGGED = text_paths(PAIR_RE.sub('', HAND))        # mentions with no readable verb

FORCE = set(PINS.get('generate_despite_handwritten', []))
HIDDEN = []   # operations the path-only gate counts as present but no hand-written code implements


def is_missing(m, p):
    c = canon(p)
    if f'{m.upper()} {p}' in FORCE:
        return True
    missing = (m, c) not in PAIRS and c not in UNTAGGED
    if missing and c in HAND_PATHS:
        HIDDEN.append(f'{m.upper()} {p}')
    return missing


# ── schemas -> models ────────────────────────────────────────────────────────
MODELS = collections.OrderedDict()   # class name -> list of (ruby name, json key, type expr)
BY_KEY = {}                          # canonical json -> class name


def scalar_type(s):
    t = s.get('type')
    if isinstance(t, list):
        t = next((x for x in t if x != 'null'), None)
    if 'const' in s:
        return {str: ':string', bool: ':boolean', int: ':integer', float: ':number'}.get(type(s['const']), ':any')
    return {'string': ':string', 'integer': ':integer', 'number': ':number', 'boolean': ':boolean'}.get(t)


def collect_props(s, depth=0):
    """Properties of an object schema, merging allOf and the object members of anyOf/oneOf."""
    s = deref(s)
    props = collections.OrderedDict()
    if depth > 6:
        return props
    for k in ('allOf', 'anyOf', 'oneOf'):
        for sub in s.get(k, []):
            for n, v in collect_props(sub, depth + 1).items():
                if n not in props:
                    props[n] = v
                elif k != 'allOf' and props[n] != v:
                    # the same field in several variants: keep every variant's shape
                    cur = props[n]
                    props[n] = {'oneOf': (cur['oneOf'] if set(cur) == {'oneOf'} else [cur]) + [v]}
    for n, v in (s.get('properties') or {}).items():
        props[n] = v
    return props


def is_nullable_union(s):
    subs = s.get('anyOf') or s.get('oneOf')
    if not subs:
        return None
    real = [x for x in subs if deref(x).get('type') != 'null' and not ('const' in deref(x) and deref(x)['const'] is None)]
    return real[0] if len(real) == 1 else None


def type_expr(schema, hint):
    """Ruby type expression for a schema: :string | "Model" | [type] | { map: type }."""
    raw = schema if isinstance(schema, dict) else {}
    s = deref(raw)
    ref = raw.get('$ref')
    inner = is_nullable_union(s)
    if inner is not None:
        return type_expr(inner, hint)
    sc = scalar_type(s)
    if sc:
        return sc
    t = s.get('type')
    if t == 'array' or 'items' in s:
        return '[' + type_expr(s.get('items', {}), hint + 'Item') + ']'
    props = collect_props(s)
    if props:
        return rq(model_for(raw, hint))
    if t == 'object' or 'additionalProperties' in s:
        ap = s.get('additionalProperties')
        if isinstance(ap, dict) and ap:
            sub = type_expr(ap, hint + 'Value')
            return '{ map: ' + sub + ' }' if sub != ':any' else ':hash'
        return ':hash'
    return ':any'


def model_for(schema, hint):
    raw = schema if isinstance(schema, dict) else {}
    s = deref(raw)
    ref = raw.get('$ref')
    key = ref or json.dumps(s, sort_keys=True)
    obj = (collect_props(s).get('object') or {})
    obj = deref(obj).get('const')
    if ref:
        base = camel(ref.split('/')[-1])
    elif isinstance(obj, str) and obj != 'list' and re.fullmatch(r'[a-z][a-z0-9_.]*', obj):
        base = camel(obj)   # the API's own name for the object: one model for the same object everywhere
    else:
        base = camel(hint)
    name = base or 'Value'
    # a name already published (pinned) is emitted even when a new op reached this shape first
    if key in BY_KEY and not (name in PINS.get('models', []) and name not in MODELS):
        return BY_KEY[key]
    if name in MODELS or name in ('Model', 'Page'):
        i = 2
        while f'{name}{i}' in MODELS:
            i += 1
        name = f'{name}{i}'
    BY_KEY.setdefault(key, name)
    MODELS[name] = None   # reserve so recursion sees it
    attrs, used = [], set()
    for jk, ps in collect_props(s).items():
        rn = snake(jk) or 'field'
        if not re.fullmatch(r'[a-z]\w*', rn):
            rn = 'f_' + rn
        if rn in RUBY_KW or rn in RUBY_OBJ:
            rn += '_'
        base_rn, i = rn, 2
        while rn in used:
            rn = f'{base_rn}_{i}'
            i += 1
        used.add(rn)
        attrs.append((rn, jk, type_expr(ps, name + camel(jk))))
    MODELS[name] = attrs
    return name


def success_schema(o):
    for code, r in sorted(o.get('responses', {}).items()):
        if code.startswith('2'):
            c = r.get('content', {})
            if 'application/json' in c:
                return c['application/json'].get('schema', {}), 'json'
            if c:
                return None, 'raw'
            return None, 'none'
    return None, 'none'


ENVELOPE_KEYS = {'object', 'data', 'has_more', 'next_cursor'}


def envelope_model(s, m, p):
    """A model for the whole list answer when it carries more than the page itself, else None."""
    if set(collect_props(s)) - ENVELOPE_KEYS:
        return model_for(s, op_hint(m, p) + 'List')
    return None


def op_hint(m, p):
    segs = [camel(x) for x in p.split('/')[2:] if not x.startswith('{')]
    return m.capitalize() + ''.join(segs) + 'Response'


# ── naming ───────────────────────────────────────────────────────────────────
def segments(p):
    parts = p.strip('/').split('/')[1:]
    return parts[0], [(x.startswith('{'), x.strip('{}')) for x in parts[1:]]


def list_like(o, schema):
    s = deref(schema or {})
    props = collect_props(s)
    return 'data' in props and deref(props['data']).get('type') == 'array'


def name_candidates(m, p, o, listy):
    group, segs = segments(p)
    g = snake(group)
    statics = [snake(x) for ip, x in segs if not ip]
    ends_param = bool(segs) and segs[-1][0]
    chain = statics or [g]
    last = chain[-1]
    verbs = {'get': 'get', 'post': 'create', 'put': 'set', 'patch': 'update', 'delete': 'delete'}
    cands = []
    action = None
    if m == 'post' and not ends_param and statics and not last.endswith('s'):
        action = last
    if action:
        rest = statics[:-1]
        cands.append(f'{action}_{sing(rest[-1])}' if rest else action)
        cands.append('_'.join([action] + [sing(x) for x in rest]) or action)
    elif m == 'get' and not ends_param:
        v = 'list' if listy else 'get'
        cands.append(f'{v}_{last}')
        cands.append(f'{v}_' + '_'.join(chain))
    else:
        v = verbs[m]
        noun = sing(last) if (ends_param or m in ('post',) or not statics or m == 'delete') else last
        cands.append(f'{v}_{noun}')
        cands.append(f'{v}_' + '_'.join(chain[:-1] + [noun]))
    pnames = [snake(x) for ip, x in segs if ip]
    cands.append(cands[-1] + ('_by_' + pnames[-1] if pnames else '_all'))
    cands.append(cands[-1] + '_' + m)
    return [c if c not in RUBY_KW and c not in RUBY_OBJ else c + '_op' for c in cands]


# ── existing hand-written surface ────────────────────────────────────────────
client_src = open(os.path.join(LIB, 'atlas', 'client.rb')).read()
CLIENT_DEFS = set(re.findall(r'^\s*def (\w+)', client_src, re.M))
ACCESSOR_CLASS = {a: c for a, c in re.findall(r'def (\w+)\s*=\s*@\w+ \|\|= Resources::(\w+)\.new\(@transport\)', client_src)}
RES_FILES = {}
for f in glob.glob(os.path.join(LIB, 'atlas', 'resources', '*.rb')):
    t = open(f).read()
    for c in re.findall(r'^\s*class (\w+)', t, re.M):
        RES_FILES.setdefault(c, []).append(t)


def existing_methods(cls):
    out = set()
    for t in RES_FILES.get(cls, []):
        out |= set(re.findall(r'^\s*def (?:self\.)?(\w+[?!]?)', t, re.M))
    return out


# ── build per-group methods ──────────────────────────────────────────────────
GROUPS = collections.OrderedDict()   # group -> list of dict(op)
for m, p, o in ops:
    if not is_missing(m, p):
        continue
    GROUPS.setdefault(segments(p)[0], []).append((m, p, o))

OPERATIONS = {}      # "GET /path" -> model name | "Name[]"
KEYWORDS_SENT = {}


def build_method(m, p, o, name):
    """Ruby source lines for one operation, plus test info."""
    group, segs = segments(p)
    params = [deref(x) for x in o.get('parameters', [])]
    used = {'idempotency_key', 'body', 'query'}
    # path params, in the order they appear in the path
    pos = []
    for ip, x in segs:
        if ip:
            n = safe_ident(x) or 'id'
            while n in used:
                n += '_id'
            used.add(n)
            pos.append((n, x))
    qp = [x for x in params if x.get('in') == 'query']
    has_idem = any(x.get('in') == 'header' and x.get('name', '').lower() == 'idempotency-key' for x in params)
    kw_req, kw_opt, body_pairs, query_pairs = [], [], [], []
    # query
    query_fallback = any(safe_ident(x['name']) is None for x in qp)
    for x in qp:
        if query_fallback:
            break
        n = safe_ident(x['name'])
        while n in used:
            n += '_query'
        used.add(n)
        query_pairs.append((n, x['name']))
        (kw_req if x.get('required') else kw_opt).append(n)
    # body
    body_mode = None   # None | 'kw' | 'hash' | 'hash_req' | 'raw'
    bs = None
    rbody = o.get('requestBody') or {}
    content = rbody.get('content', {})
    if 'application/json' in content:
        bs = deref(content['application/json'].get('schema', {}))
        props = collect_props(bs)
        has_variants = bool(bs.get('oneOf') or bs.get('anyOf'))
        if props and not has_variants and all(safe_ident(k) for k in props) and bs.get('type', 'object') == 'object':
            body_mode = 'kw'
            req = set(bs.get('required', []))
            for allof in bs.get('allOf', []):
                req |= set(deref(allof).get('required', []))
            for k in props:
                n = safe_ident(k)
                while n in used:
                    n += '_body'
                used.add(n)
                body_pairs.append((n, k))
                (kw_req if k in req else kw_opt).append(n)
        else:
            body_mode = 'hash_req' if rbody.get('required') else 'hash'
    elif content:
        body_mode = 'raw'
    sig = [n for n, _ in pos]
    if body_mode == 'hash_req':
        sig.append('body')
    elif body_mode == 'hash':
        sig.append('body = {}')
    if body_mode == 'raw':
        kw_req += ['raw_body', 'content_type']
    if query_fallback:
        kw_opt.append('query')
    sig += [f'{n}:' for n in kw_req] + [f'{n}: UNSET' for n in kw_opt]
    if has_idem:
        sig.append('idempotency_key: nil')
    # path literal
    path_expr = '/v1/' + group
    it = iter(pos)
    for ip, x in segs:
        path_expr += '/' + (('#{enc(' + next(it)[0] + ')}') if ip else x)
    # response
    rs, rkind = success_schema(o)
    listy = rkind == 'json' and list_like(o, rs)
    wrap_open, wrap_close, ret = '', '', 'Hash'
    page = False
    if rkind == 'json':
        s = deref(rs)
        if listy:
            item = collect_props(s)['data'].get('items', {})
            im = model_for(item, op_hint(m, p) + 'Item') if collect_props(item) else None
            page = True
            ret = f'Page<{im or "Hash"}>'
            env = envelope_model(s, m, p)
            OPERATIONS[f'{m.upper()} {p}'] = (im or '') + '[]' + (':' + env if env else '')
            item_model = f'M::{im}' if im else 'nil'
            envelope_arg = f', envelope: M::{env}' if env else ''
        elif collect_props(s):
            mn = model_for(rs, op_hint(m, p))
            OPERATIONS[f'{m.upper()} {p}'] = mn
            wrap_open, wrap_close, ret = f'G.wrap(M::{mn}, ', ')', f'Atlas::Models::{mn}'
        elif s.get('type') == 'array' or 'items' in s:
            ret = 'Array'
    lines = []
    summary = (o.get('summary') or '').strip()
    if summary:
        lines.append(f'# {summary}')
    lines.append(f'# `{m.upper()} {p}`' + (f' (scope: {o["x-required-scope"]})' if o.get('x-required-scope') else ''))
    if rkind == 'none':
        ret = 'nil'
    lines.append(f'# @return [{ret}]')
    lines.append(f'def {name}({", ".join(sig)})')
    # query
    qlit = None
    if query_pairs or query_fallback:
        if query_fallback:
            lines.append('  query = G.compact(query) # shortcut: query names that are not Ruby identifiers go in as one Hash')
            qvar = 'query'
        else:
            lines.append('  query = G.compact(' + ', '.join(f'{rq(j)} => {n}' for n, j in query_pairs) + ')')
            qvar = 'query'
        qlit = qvar
    call_args = [f'method: :{m}', 'path: "' + path_expr + '"']
    if page:
        call_args.append('query: q')
    elif qlit:
        call_args.append('query: query')
    if body_mode == 'kw':
        lines.append('  body = G.compact(' + ', '.join(f'{rq(j)} => {n}' for n, j in body_pairs) + ')')
        call_args.append('body: body')
    elif body_mode in ('hash', 'hash_req'):
        call_args.append('body: body')
    elif body_mode == 'raw':
        call_args.append('raw_body: raw_body, content_type: content_type')
    if has_idem:
        call_args.append('idempotency_key: idempotency_key')
    if rkind == 'raw':
        call_args.append('raw: true')
    call = 'request(' + ', '.join(call_args) + ')'
    if page:
        lines.append(f'  G.page({item_model}, {qlit or "{}"}{envelope_arg}) {{ |q| {call} }}')
    else:
        lines.append(f'  {wrap_open}{call}{wrap_close}')
    lines.append('end')
    info = dict(name=name, m=m, p=p, pos=len(pos), req=kw_req, body=body_mode, has_idem=has_idem,
                body_pairs=dict((n, j) for n, j in body_pairs), body_schema=bs, page=page, rkind=rkind)
    return lines, info


# assign names per group, then emit
catalog_lines = [
    '# frozen_string_literal: true', '',
    '# GENERATED by scripts/gen_catalog.py from scripts/openapi.snapshot.json. Do not edit by hand.', '',
    'require_relative "../model"', 'require_relative "../resources/base"', 'require_relative "models"', '',
    'module Atlas', '  # The long tail of the Backend API: every operation the hand-written resources do not cover.',
    '  # Each group is a module of keyword-argument methods; see Atlas::Generated::Page for lists.',
    '  module Generated', '    G = Atlas::Generated', '    M = Atlas::Models', '',
]
INFOS = []
ACCESSORS = []
INCLUDES = []
new_pins = {}
stale = [k for k in PINS.get('names', {}) if not any(f'{m.upper()} {p}' == k for m, p, _ in ops)]
n_methods = 0
for group in sorted(GROUPS):
    cls = camel(group)
    existing_cls = ACCESSOR_CLASS.get(snake(group))
    taken = set(existing_methods(existing_cls)) if existing_cls else set()
    taken |= {'initialize', 'request', 'enc', 'transport'}
    chosen = {}
    items = GROUPS[group]
    # pinned names first so they never move
    for m, p, o in items:
        key = f'{m.upper()} {p}'
        pin = PINS.get('names', {}).get(key)
        if pin and pin not in taken:
            chosen[key] = pin
            taken.add(pin)
    for m, p, o in items:
        key = f'{m.upper()} {p}'
        if key in chosen:
            continue
        rs, rkind = success_schema(o)
        cands = name_candidates(m, p, o, rkind == 'json' and list_like(o, rs))
        pick = next((c for c in cands if c not in taken), None)
        i = 2
        while pick is None:
            pick = f'{cands[0]}_{i}'
            if pick in taken:
                pick, i = None, i + 1
        chosen[key] = pick
        taken.add(pick)
    catalog_lines += [f'    # /v1/{group}', f'    module {cls}Operations']
    first = True
    for m, p, o in items:
        key = f'{m.upper()} {p}'
        body, info = build_method(m, p, o, chosen[key])
        new_pins[key] = chosen[key]
        INFOS.append((group, info))
        if not first:
            catalog_lines.append('')
        first = False
        catalog_lines += ['      ' + l for l in body]
        n_methods += 1
    catalog_lines += ['    end', '']
    if existing_cls:
        INCLUDES.append((existing_cls, cls))
    else:
        acc = snake(group)
        if acc in CLIENT_DEFS or acc in RUBY_OBJ:
            acc += '_ext'
        ACCESSORS.append((acc, cls))
        catalog_lines += [f'    # Namespace for /v1/{group} (`client.{acc}`).',
                          f'    class {cls}Api < Atlas::Resources::Base', f'      include {cls}Operations', '    end', '']
for ec, cls in INCLUDES:
    catalog_lines += [f'    Atlas::Resources::{ec}.include({cls}Operations)']
catalog_lines += ['', '    # Client accessors for the groups that have no hand-written namespace.',
                  '    module Accessors']
for acc, cls in ACCESSORS:
    catalog_lines += [f'      def {acc} = @{acc} ||= Atlas::Generated::{cls}Api.new(@transport)']
catalog_lines += ['    end', '  end', 'end', '', 'Atlas::Client.include(Atlas::Generated::Accessors)', '']

# ── models for every other operation (so hand-written calls can be wrapped) ──
for m, p, o in ops:
    key = f'{m.upper()} {p}'
    if key in OPERATIONS:
        continue
    rs, rkind = success_schema(o)
    if rkind != 'json':
        continue
    s = deref(rs)
    if list_like(o, rs):
        item = collect_props(s)['data'].get('items', {})
        if collect_props(item):
            env = envelope_model(s, m, p)
            OPERATIONS[key] = model_for(item, op_hint(m, p) + 'Item') + '[]' + (':' + env if env else '')
    elif collect_props(s):
        OPERATIONS[key] = model_for(rs, op_hint(m, p))

# ── write models.rb ──────────────────────────────────────────────────────────
ml = ['# frozen_string_literal: true', '',
      '# GENERATED by scripts/gen_catalog.py from scripts/openapi.snapshot.json. Do not edit by hand.', '',
      'require_relative "../model"', '', 'module Atlas', '  # Typed response models. Each wraps the JSON Hash the API returned: accessors read the',
      '  # declared fields (nested objects and lists come back as models), `[]` / `#to_h` still give',
      '  # the raw data, and fields the SDK does not know yet are never lost.', '  module Models']
for name in sorted(MODELS):
    ml.append(f'    class {name} < Atlas::Model')
    for rn, jk, te in MODELS[name]:
        ml.append(f'      attribute :{rn}, {rq(jk)}, {te}')
    if not MODELS[name]:
        ml.append('      # no declared fields')
    ml.append('    end')
    ml.append('')
ml += ['    # Which model each operation answers with ("Name[]" is a list page of Name).', '    OPERATIONS = {']
for k in sorted(OPERATIONS, key=lambda k: (k.split(' ', 1)[1], k)):
    ml.append(f'      {rq(k)} => {rq(OPERATIONS[k])},')
ml += ['    }.freeze', '  end', 'end', '']

# ── tests ────────────────────────────────────────────────────────────────────
def sample(schema, depth=0):
    s = deref(schema or {})
    t = s.get('type')
    if 'enum' in s:
        return rq(str(s['enum'][0]))
    if t == 'integer' or t == 'number':
        return '1'
    if t == 'boolean':
        return 'true'
    if t == 'array':
        return '[]'
    if t == 'object' or collect_props(s):
        return '{}'
    return '"x"'


tl = ['# frozen_string_literal: true', '',
      '# GENERATED by scripts/gen_catalog.py. Do not edit by hand.', '',
      'require_relative "../test_helper"', '', 'class GeneratedCatalogTest < Minitest::Test',
      '  def client(stub)', '    Atlas::Client.new("sk_test_x", api_url: "https://api.test", http: stub)', '  end', '',
      '  def call(method, path)',
      '    stub = Atlas::Test::StubRequester.new.enqueue(status: 200, body: {})',
      '    yield client(stub)',
      '    req = stub.last',
      '    assert_equal method, req.method',
      '    assert_equal "https://api.test#{path}", req.url.split("?").first',
      '    req',
      '  end', '']
for group, info in INFOS:
    args = ['"p%d"' % (i + 1) for i in range(info['pos'])]
    if info['body'] == 'hash_req':
        args.append('{}')
    kws = []
    bs = info['body_schema']
    props = collect_props(bs) if bs else {}
    inv = {n: j for n, j in info['body_pairs'].items()}
    for n in info['req']:
        if n == 'raw_body':
            kws.append('raw_body: "x"')
        elif n == 'content_type':
            kws.append('content_type: "image/png"')
        elif n in inv:
            kws.append(f'{n}: {sample(props.get(inv[n], {}))}')
        else:
            kws.append(f'{n}: "x"')
    callargs = ', '.join(args + kws)
    # rebuild the concrete path with the sample ids
    _, segs = segments(info['p'])
    it = iter(range(1, 100))
    concrete = '/v1/' + group + ''.join('/' + (f'p{next(it)}' if ip else x) for ip, x in segs)
    acc = next((a for a, c in ACCESSORS if c == camel(group)), None) or snake(group)
    tl.append(f'  def test_{info["m"]}_{re.sub(r"[^a-z0-9]+", "_", info["p"].lower()).strip("_")}')
    tl.append(f'    call({rq(info["m"].upper())}, {rq(concrete)}) {{ |c| c.{acc}.{info["name"]}({callargs}) }}')
    tl.append('  end')
    tl.append('')
tl.append('end')
tl.append('')

# ── request fields of the operations the hand-written resources already implement ─
SHORT = {'string': ':string', 'integer': ':integer', 'number': ':number', 'boolean': ':boolean', 'array': ':array', 'object': ':hash'}
# every operation with a body or query is listed (nested field names included), generated or not
generated_keys = {f"{i['m'].upper()} {i['p']}" for _, i in INFOS if i['body'] in (None, 'raw') and not i['body_schema']}
rl = ['# frozen_string_literal: true', '',
      '# GENERATED by scripts/gen_catalog.py from scripts/openapi.snapshot.json. Do not edit by hand.', '',
      'require_relative "../model"', '', 'module Atlas', '  module Requests',
      '    # Body and query fields of the operations the hand-written resources implement, for',
      '    # Atlas::Requests.body / .query (typed keyword arguments in, the request Hash out).',
      '    FIELDS = {']
for m, p, o in ops:
    key = f'{m.upper()} {p}'
    if key in generated_keys:
        continue
    bodyp, req = {}, []
    content = (o.get('requestBody') or {}).get('content', {})
    if 'application/json' in content:
        bs = deref(content['application/json'].get('schema', {}))
        bodyp = collect_props(bs)
        req = list(bs.get('required', []))
    qs = [deref(x) for x in o.get('parameters', []) if deref(x).get('in') == 'query']
    if not bodyp and not qs:
        continue
    def short(v, depth=0):
        v = deref(v)
        t = v.get('type')
        t = next((x for x in t if x != 'null'), None) if isinstance(t, list) else t
        sub = collect_props(v) if depth < 4 else {}
        if sub and t in (None, 'object'):
            return '{ ' + ', '.join(f'{rq(k)} => {short(x, depth + 1)}' for k, x in sub.items()) + ' }'
        if t == 'array' and depth < 4:
            it = deref(v.get('items', {}))
            if collect_props(it):
                return '[' + short(it, depth + 1) + ']'
        return SHORT.get(t, ':any')
    parts = []
    if bodyp:
        parts.append('"body" => { ' + ', '.join(f'{rq(k)} => {short(v)}' for k, v in bodyp.items()) + ' }')
        if req:
            parts.append('"required" => [' + ', '.join(rq(r) for r in req) + ']')
    if qs:
        parts.append('"query" => [' + ', '.join(rq(x['name']) for x in qs) + ']')
    rl.append(f'      {rq(key)} => {{ ' + ', '.join(parts) + ' },')
rl += ['    }.freeze', '  end', 'end', '']

# ── write ────────────────────────────────────────────────────────────────────
os.makedirs(GEN_DIR, exist_ok=True)
os.makedirs(os.path.join(ROOT, 'test', 'generated'), exist_ok=True)
for path, lines in ((os.path.join(GEN_DIR, 'catalog.rb'), catalog_lines), (os.path.join(GEN_DIR, 'models.rb'), ml), (os.path.join(GEN_DIR, 'requests.rb'), rl),
                    (os.path.join(ROOT, 'test', 'generated', 'catalog_test.rb'), tl)):
    with open(path, 'w') as f:
        f.write('\n'.join(lines))

if '--pin' in sys.argv:
    merged = dict(PINS.get('names', {}))
    merged.update(new_pins)
    PINS['names'] = dict(sorted(merged.items()))
    PINS['models'] = sorted(set(PINS.get('models', [])) | set(MODELS))
    with open(os.path.join(HERE, 'catalog_pins.json'), 'w') as f:
        json.dump(PINS, f, indent=1)
        f.write('\n')
if stale:
    print('note: pinned names the spec no longer reaches (ignored):', len(stale))
if '--report' in sys.argv or True:
    print(f'{len(HIDDEN)} of them share a path with a hand-written operation (hidden from the path-only drift gate)')
    print(f'generated {n_methods} operations in {len(GROUPS)} groups, {len(MODELS)} models, {len(OPERATIONS)} wrapped operations')
