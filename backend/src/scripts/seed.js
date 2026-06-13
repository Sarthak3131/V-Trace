'use strict';

const mongoose = require('mongoose');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');

// Inject environment variables from .env
dotenv.config({ path: path.join(__dirname, '../../.env') });

const connectDB = require('../config/db');
const User = require('../models/User');
const Case = require('../models/Case');
const Content = require('../models/Content');
const AIAnalysisResult = require('../models/AIAnalysisResult');
const AuditLog = require('../models/AuditLog');
const SkillKnowledgeBase = require('../models/SkillKnowledgeBase');
const ATSReport = require('../models/ATSReport');
const ATSResume = require('../models/ATSResume');
const ATSJobDescription = require('../models/ATSJobDescription');

// Merkle Tree Helper Functions
function hashPair(leftHex, rightHex) {
  const left = Buffer.from(leftHex, 'hex');
  const right = Buffer.from(rightHex, 'hex');
  const concatenated = Buffer.concat([left, right]);
  return crypto.createHash('sha256').update(concatenated).digest('hex');
}

function buildMerkleRoot(hashes) {
  if (hashes.length === 0) return '';
  if (hashes.length === 1) return hashes[0];
  let currentLevel = hashes.map((h) => h.toLowerCase());
  while (currentLevel.length > 1) {
    const nextLevel = [];
    const nodes = currentLevel.length % 2 === 0
      ? currentLevel
      : [...currentLevel, currentLevel[currentLevel.length - 1]];
    for (let i = 0; i < nodes.length; i += 2) {
      nextLevel.push(hashPair(nodes[i], nodes[i + 1]));
    }
    currentLevel = nextLevel;
  }
  return currentLevel[0];
}

// Chained Cryptographic Logging Helper
let currentPrevHash = 'GENESIS_HASH_SEED_V_TRACE';
let currentLogTime = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000); // Start 4 days ago

async function seedAuditLog({ action, entityType, entityId, performedBy, details }) {
  // Increment by 15 minutes for each log entry to ensure strict chronological sorting order
  currentLogTime = new Date(currentLogTime.getTime() + 15 * 60 * 1000);
  const timestamp = new Date(currentLogTime);
  const detailsStr = details ? JSON.stringify(details) : '{}';

  // Format: action|entityType|entityId|performedBy|details|timestamp|previousLogHash
  const serialized = `${action}|${entityType}|${entityId ? entityId.toString() : ''}|${
    performedBy ? performedBy.toString() : ''
  }|${detailsStr}|${timestamp.toISOString()}|${currentPrevHash}`;

  const hash = crypto.createHash('sha256').update(serialized).digest('hex');

  const log = await AuditLog.create({
    action,
    entityType,
    entityId,
    performedBy,
    details: details || {},
    timestamp,
    previousLogHash: currentPrevHash,
    hash,
  });

  currentPrevHash = hash;
  return log;
}

async function runSeed() {
  try {
    await connectDB();

    console.log('Clearing database collections...');
    await User.deleteMany({});
    await Case.deleteMany({});
    await Content.deleteMany({});
    await AIAnalysisResult.deleteMany({});
    await AuditLog.deleteMany({});
    await SkillKnowledgeBase.deleteMany({});
    await ATSReport.deleteMany({});
    await ATSResume.deleteMany({});
    await ATSJobDescription.deleteMany({});
    console.log('Database cleared.');

    console.log('Seeding Users...');
    const admin = await User.create({
      name: 'Director Arthur Vance',
      email: 'admin@vtrace.ai',
      password: 'password123',
      role: 'admin',
      isActive: true,
    });

    const userSarthak = await User.create({
      name: 'Sarthak Srivastava',
      email: 'sarthaksrivastava189@gmail.com',
      password: 'Sarthak@321',
      role: 'admin',
      isActive: true,
    });

    const investigator1 = await User.create({
      name: 'Agent Sarah Connor',
      email: 'investigator1@vtrace.ai',
      password: 'password123',
      role: 'moderator',
      isActive: true,
    });

    const investigator2 = await User.create({
      name: 'Agent John Doe',
      email: 'investigator2@vtrace.ai',
      password: 'password123',
      role: 'moderator',
      isActive: true,
    });

    const standardUser = await User.create({
      name: 'Analyst Jane Smith',
      email: 'user1@vtrace.ai',
      password: 'password123',
      role: 'user',
      isActive: true,
    });

    console.log(`Users seeded. Admin ID: ${admin._id}, Investigator1 ID: ${investigator1._id}`);

    console.log('Seeding SkillKnowledgeBase (800+ skills)...');
    
    // Core Hand-Crafted Skills
    const coreSkills = [
      // Frontend
      { canonicalName: 'react', aliases: ['react.js', 'reactjs', 'react-js'], category: 'frontend', popularityScore: 98, relatedSkills: ['redux', 'next.js', 'typescript'] },
      { canonicalName: 'angular', aliases: ['angular.js', 'angularjs'], category: 'frontend', popularityScore: 85, relatedSkills: ['typescript', 'rxjs', 'html'] },
      { canonicalName: 'vue', aliases: ['vue.js', 'vuejs'], category: 'frontend', popularityScore: 88, relatedSkills: ['vuex', 'nuxt', 'javascript'] },
      { canonicalName: 'next.js', aliases: ['nextjs', 'next'], category: 'frontend', popularityScore: 95, relatedSkills: ['react', 'vercel', 'ssr'] },
      { canonicalName: 'nuxt', aliases: ['nuxt.js', 'nuxtjs'], category: 'frontend', popularityScore: 78, relatedSkills: ['vue', 'ssr'] },
      { canonicalName: 'svelte', aliases: ['sveltekit', 'svelte.js'], category: 'frontend', popularityScore: 80, relatedSkills: ['html', 'css', 'javascript'] },
      { canonicalName: 'javascript', aliases: ['js', 'es6', 'ecmascript'], category: 'frontend', popularityScore: 99, relatedSkills: ['html', 'css', 'typescript'] },
      { canonicalName: 'typescript', aliases: ['ts', 'tsc'], category: 'frontend', popularityScore: 96, relatedSkills: ['javascript', 'node', 'react'] },
      { canonicalName: 'tailwind', aliases: ['tailwindcss', 'tailwind-css'], category: 'frontend', popularityScore: 92, relatedSkills: ['css', 'html', 'postcss'] },
      { canonicalName: 'html', aliases: ['html5', 'xhtml'], category: 'frontend', popularityScore: 99, relatedSkills: ['css', 'javascript'] },
      { canonicalName: 'css', aliases: ['css3', 'flexbox', 'grid'], category: 'frontend', popularityScore: 99, relatedSkills: ['html', 'javascript'] },
      { canonicalName: 'redux', aliases: ['redux-toolkit', 'rtk'], category: 'frontend', popularityScore: 85, relatedSkills: ['react', 'state-management'] },
      
      // Backend
      { canonicalName: 'node', aliases: ['node.js', 'nodejs'], category: 'backend', popularityScore: 95, relatedSkills: ['express', 'npm', 'javascript'] },
      { canonicalName: 'express', aliases: ['express.js', 'expressjs'], category: 'backend', popularityScore: 90, relatedSkills: ['node', 'mongodb', 'rest api'] },
      { canonicalName: 'nest.js', aliases: ['nestjs', 'nest'], category: 'backend', popularityScore: 82, relatedSkills: ['typescript', 'node', 'graphql'] },
      { canonicalName: 'django', aliases: ['django-framework'], category: 'backend', popularityScore: 85, relatedSkills: ['python', 'postgresql', 'flask'] },
      { canonicalName: 'flask', aliases: ['flask-framework'], category: 'backend', popularityScore: 78, relatedSkills: ['python', 'django', 'fastapi'] },
      { canonicalName: 'fastapi', aliases: ['fast-api'], category: 'backend', popularityScore: 88, relatedSkills: ['python', 'pydantic', 'starlette'] },
      { canonicalName: 'spring boot', aliases: ['springboot', 'spring-boot'], category: 'backend', popularityScore: 90, relatedSkills: ['java', 'hibernate', 'microservices'] },
      { canonicalName: 'laravel', aliases: ['laravel-framework'], category: 'backend', popularityScore: 80, relatedSkills: ['php', 'mysql', 'composer'] },
      { canonicalName: 'rest api', aliases: ['rest apis', 'restful api', 'restful apis', 'rest'], category: 'backend', popularityScore: 98, relatedSkills: ['graphql', 'json', 'http'] },
      { canonicalName: 'graphql', aliases: ['graphql-api'], category: 'backend', popularityScore: 84, relatedSkills: ['apollo', 'rest api', 'relay'] },
      
      // Database
      { canonicalName: 'mongodb', aliases: ['mongo', 'mongodb-database'], category: 'database', popularityScore: 92, relatedSkills: ['mongoose', 'nosql', 'express'] },
      { canonicalName: 'mysql', aliases: ['mysql-database', 'my-sql'], category: 'database', popularityScore: 90, relatedSkills: ['sql', 'php', 'postgresql'] },
      { canonicalName: 'postgresql', aliases: ['postgres', 'postgresql-database'], category: 'database', popularityScore: 94, relatedSkills: ['sql', 'mysql', 'pgadmin'] },
      { canonicalName: 'redis', aliases: ['redis-cache'], category: 'database', popularityScore: 88, relatedSkills: ['memcached', 'caching', 'node'] },
      { canonicalName: 'elasticsearch', aliases: ['elastic', 'elk'], category: 'database', popularityScore: 82, relatedSkills: ['logstash', 'kibana', 'lucene'] },
      { canonicalName: 'sql', aliases: ['structured query language'], category: 'database', popularityScore: 96, relatedSkills: ['mysql', 'postgresql', 'oracle'] },

      // Cloud
      { canonicalName: 'aws', aliases: ['amazon web services', 'amazon-aws'], category: 'cloud', popularityScore: 98, relatedSkills: ['s3', 'ec2', 'lambda', 'devops'] },
      { canonicalName: 'gcp', aliases: ['google cloud platform', 'google-cloud'], category: 'cloud', popularityScore: 88, relatedSkills: ['bigquery', 'gke', 'cloud run'] },
      { canonicalName: 'azure', aliases: ['microsoft azure', 'azure-cloud'], category: 'cloud', popularityScore: 90, relatedSkills: ['active-directory', 'aks', 'azure-functions'] },
      { canonicalName: 'docker', aliases: ['docker-containers'], category: 'cloud', popularityScore: 95, relatedSkills: ['kubernetes', 'devops', 'containers'] },
      { canonicalName: 'kubernetes', aliases: ['k8s', 'kube'], category: 'cloud', popularityScore: 92, relatedSkills: ['docker', 'helm', 'devops'] },
      
      // DevOps
      { canonicalName: 'git', aliases: ['git-vcs'], category: 'devops', popularityScore: 99, relatedSkills: ['github', 'gitlab', 'version-control'] },
      { canonicalName: 'github', aliases: ['github-vcs'], category: 'devops', popularityScore: 98, relatedSkills: ['git', 'github-actions', 'gitlab'] },
      { canonicalName: 'jenkins', aliases: ['jenkins-ci'], category: 'devops', popularityScore: 80, relatedSkills: ['ci/cd', 'docker', 'pipelines'] },
      { canonicalName: 'terraform', aliases: ['tf', 'iac'], category: 'devops', popularityScore: 88, relatedSkills: ['ansible', 'aws', 'kubernetes'] },
      { canonicalName: 'ansible', aliases: ['ansible-automation'], category: 'devops', popularityScore: 82, relatedSkills: ['terraform', 'chef', 'puppet'] },

      // AI/ML
      { canonicalName: 'pytorch', aliases: ['torch'], category: 'ai/ml', popularityScore: 94, relatedSkills: ['python', 'tensorflow', 'deep-learning'] },
      { canonicalName: 'tensorflow', aliases: ['tf-ml'], category: 'ai/ml', popularityScore: 90, relatedSkills: ['keras', 'pytorch', 'python'] },
      { canonicalName: 'numpy', aliases: ['numpy-py'], category: 'ai/ml', popularityScore: 92, relatedSkills: ['pandas', 'scipy', 'python'] },
      { canonicalName: 'pandas', aliases: ['pandas-py'], category: 'ai/ml', popularityScore: 92, relatedSkills: ['numpy', 'matplotlib', 'python'] },
      { canonicalName: 'opencv', aliases: ['opencv-cv'], category: 'ai/ml', popularityScore: 85, relatedSkills: ['python', 'c++', 'computer-vision'] },
      { canonicalName: 'langchain', aliases: ['langchain-ai'], category: 'ai/ml', popularityScore: 88, relatedSkills: ['llm', 'openai', 'gpt'] },
      { canonicalName: 'openai', aliases: ['chatgpt', 'gpt4'], category: 'ai/ml', popularityScore: 96, relatedSkills: ['llm', 'api', 'langchain'] },

      // Product
      { canonicalName: 'jira', aliases: ['atlassian-jira'], category: 'product', popularityScore: 92, relatedSkills: ['confluence', 'agile', 'scrum'] },
      { canonicalName: 'scrum', aliases: ['scrum-framework'], category: 'product', popularityScore: 90, relatedSkills: ['agile', 'kanban', 'jira'] },
      { canonicalName: 'agile', aliases: ['agile-methodology'], category: 'product', popularityScore: 94, relatedSkills: ['scrum', 'kanban', 'product-roadmap'] },
      { canonicalName: 'product management', aliases: ['product-owner', 'pm'], category: 'product', popularityScore: 88, relatedSkills: ['agile', 'figma', 'analytics'] },

      // Marketing
      { canonicalName: 'seo', aliases: ['search engine optimization'], category: 'marketing', popularityScore: 90, relatedSkills: ['sem', 'google-analytics', 'copywriting'] },
      { canonicalName: 'google ads', aliases: ['googleads', 'adwords'], category: 'marketing', popularityScore: 88, relatedSkills: ['google-analytics', 'sem', 'ppc'] },
      { canonicalName: 'hubspot', aliases: ['hubspot-crm'], category: 'marketing', popularityScore: 84, relatedSkills: ['marketing-automation', 'salesforce'] },

      // HR
      { canonicalName: 'recruiting', aliases: ['talent acquisition', 'sourcing'], category: 'hr', popularityScore: 88, relatedSkills: ['ats', 'interviewing', 'onboarding'] },
      { canonicalName: 'greenhouse', aliases: ['greenhouse-ats'], category: 'hr', popularityScore: 80, relatedSkills: ['lever', 'recruiting', 'sourcing'] },

      // Finance
      { canonicalName: 'excel', aliases: ['ms-excel', 'spreadsheets'], category: 'finance', popularityScore: 96, relatedSkills: ['financial-modeling', 'vba'] },
      { canonicalName: 'financial modeling', aliases: ['valuation', 'dcf'], category: 'finance', popularityScore: 85, relatedSkills: ['excel', 'forecasting', 'accounting'] },
      { canonicalName: 'quickbooks', aliases: ['quickbooks-accounting'], category: 'finance', popularityScore: 82, relatedSkills: ['accounting', 'xero'] }
    ];

    // Programmatically expand the list of skills to over 800
    const industries = [
      {
        category: 'frontend',
        prefix: ['react', 'vue', 'angular', 'svelte', 'ember', 'backbone', 'css', 'html', 'dom', 'npm', 'webpack', 'vite', 'yarn', 'pnpm', 'babel', 'rollup', 'esbuild', 'postcss', 'sass', 'less'],
        suffix: ['v2', 'v3', 'v4', 'v5', 'development', 'programming', 'architecture', 'routing', 'state management', 'testing', 'rendering', 'bundler', 'styles', 'responsive', 'animation', 'compiler', 'linting', 'formatting', 'optimization', 'integration']
      },
      {
        category: 'backend',
        prefix: ['node', 'express', 'nestjs', 'fastify', 'koa', 'django', 'flask', 'fastapi', 'spring', 'springboot', 'laravel', 'rails', 'phoenix', 'rocket', 'actix', 'gin', 'fiber', 'echo', 'graphql', 'grpc'],
        suffix: ['programming', 'routing', 'controllers', 'middleware', 'database connector', 'microservice', 'serverless function', 'worker queue', 'caching logic', 'authentication', 'authorization', 'rate limiting', 'validation', 'logging', 'tracing', 'deployment', 'testing', 'optimization', 'refactoring', 'monitoring']
      },
      {
        category: 'database',
        prefix: ['mongodb', 'mysql', 'postgresql', 'sqlite', 'redis', 'memcached', 'elasticsearch', 'cassandra', 'dynamodb', 'oracledb', 'mssql', 'mariadb', 'firebase', 'firestore', 'neo4j', 'arangodb', 'couchdb', 'influxdb', 'timescaledb', 'clickhouse'],
        suffix: ['querying', 'indexing', 'replication', 'sharding', 'backup', 'restoration', 'migration', 'optimization', 'procedures', 'triggers', 'clustering', 'caching', 'nosql scaling', 'schemas', 'relationships', 'views', 'security', 'monitoring', 'analyzers', 'transactions']
      },
      {
        category: 'cloud',
        prefix: ['aws', 'gcp', 'azure', 'digitalocean', 'heroku', 'netlify', 'vercel', 'firebase', 'linode', 'openstack', 'cloudflare', 'lambda', 'ec2', 's3', 'rds', 'iam', 'vpc', 'route53', 'ecs', 'eks'],
        suffix: ['infrastructure', 'deployment', 'serverless', 'virtual machine', 'blob storage', 'relational database', 'identity management', 'networking', 'dns routing', 'container service', 'kubernetes cluster', 'functions', 'hosting', 'static delivery', 'cdn caching', 'firewall security', 'compute engine', 'app services', 'alerting', 'autoscaling']
      },
      {
        category: 'devops',
        prefix: ['docker', 'kubernetes', 'jenkins', 'gitlab-ci', 'github-actions', 'circleci', 'travisci', 'terraform', 'ansible', 'chef', 'puppet', 'saltstack', 'vagrant', 'helm', 'prometheus', 'grafana', 'elk-stack', 'nginx', 'apache', 'traefik'],
        suffix: ['pipeline', 'workflows', 'containerization', 'orchestration', 'continuous integration', 'continuous delivery', 'automation', 'infrastructure as code', 'configuration management', 'provisioning', 'monitoring', 'dashboarding', 'logging', 'reverse proxy', 'load balancing', 'ingress routing', 'helm charts', 'runner scripts', 'deployment descriptors', 'alertmanager']
      },
      {
        category: 'security',
        prefix: ['cryptography', 'ssl', 'tls', 'https', 'oauth', 'jwt', 'bcrypt', 'argon2', 'hashing', 'encryption', 'aes', 'rsa', 'sha256', 'waf', 'firewall', 'vpc', 'iam', 'active-directory', 'ldap', 'keycloak'],
        suffix: ['protocols', 'tokens', 'encryption algorithms', 'security headers', 'penetration testing', 'vulnerability scanning', 'firewall rules', 'identity provider', 'access token management', 'single sign-on', 'directory service', 'owasp security checks', 'xss prevention', 'csrf protection', 'sql injection prevention', 'rate limit security', 'ddos mitigation', 'security audit', 'key management', 'secrets vault']
      },
      {
        category: 'ai/ml',
        prefix: ['pytorch', 'tensorflow', 'keras', 'jax', 'scikit-learn', 'pandas', 'numpy', 'scipy', 'opencv', 'huggingface', 'transformers', 'llm', 'gpt', 'bert', 'llama', 'langchain', 'llamaindex', 'pinecone', 'milvus', 'chromadb'],
        suffix: ['models', 'training', 'fine-tuning', 'embeddings', 'inference', 'vector search', 'deep learning', 'supervised learning', 'unsupervised learning', 'convolutional networks', 'recurrent networks', 'large language models', 'reinforcement learning', 'dataframes', 'array operations', 'image processing', 'natural language parsing', 'agent logic', 'rag pipeline', 'mlops pipelines']
      },
      {
        category: 'data science',
        prefix: ['pandas', 'numpy', 'matplotlib', 'seaborn', 'plotly', 'scipy', 'jupyter-notebook', 'anaconda', 'r-stats', 'ggplot2', 'tidyverse', 'spss', 'sas', 'stata', 'bigquery', 'snowflake', 'spark', 'pyspark', 'hadoop', 'hive'],
        suffix: ['data analysis', 'visualizations', 'statistical tests', 'scientific computing', 'interactive notebook', 'data environment', 'data warehousing', 'data lakes', 'distributed computing', 'mapreduce jobs', 'etl pipelines', 'business intelligence reports', 'data cleaning', 'feature engineering', 'hypothesis testing', 'a/b tests', 'predictive analysis', 'dashboard reporting', 'data modeling', 'tabular statistics']
      },
      {
        category: 'product',
        prefix: ['jira', 'confluence', 'trello', 'asana', 'product-roadmap', 'product-vision', 'user-stories', 'backlog-grooming', 'sprint-planning', 'okrs', 'kpis', 'product-metrics', 'mixpanel', 'amplitude', 'hotjar', 'user-research', 'figma', 'balsamiq', 'product-launch', 'go-to-market'],
        suffix: ['project management', 'documentation wiki', 'agile tracking', 'task allocation', 'roadmap milestones', 'strategic alignment', 'epic requirements', 'sprint backlogs', 'retrospective meetings', 'goal settings', 'metric analysis', 'user funnel tracking', 'heatmaps', 'usability tests', 'mockup designs', 'wireframe assets', 'release checklist', 'launch campaigns', 'retention metrics', 'customer success workflows']
      },
      {
        category: 'marketing',
        prefix: ['seo', 'sem', 'ppc', 'google-ads', 'facebook-ads', 'linkedin-ads', 'content-marketing', 'copywriting', 'email-marketing', 'mailchimp', 'hubspot', 'marketo', 'salesforce', 'social-media-marketing', 'instagram-marketing', 'brand-strategy', 'public-relations', 'affiliate-marketing', 'event-marketing', 'lead-generation'],
        suffix: ['keyword optimization', 'marketing campaigns', 'pay-per-click management', 'audience targeting', 'ad creatives', 'blog strategy', 'conversion copywriting', 'newsletter automation', 'marketing automation', 'crm integrations', 'social postings', 'brand identity', 'press releases', 'affiliate programs', 'webinar events', 'landing page optimization', 'analytics reporting', 'a/b testing ads', 'seo audits', 'inbound strategy']
      },
      {
        category: 'sales',
        prefix: ['lead-generation', 'cold-calling', 'sales-pitch', 'product-demo', 'negotiation', 'closing-deals', 'account-management', 'crm-tracking', 'salesforce-sales', 'hubspot-sales', 'pipedrive-sales', 'sales-funnel', 'sales-pipeline', 'inbound-sales', 'outbound-sales', 'enterprise-sales', 'saas-sales', 'inside-sales', 'outside-sales', 'sales-enablement'],
        suffix: ['leads list', 'outreach calls', 'pitch presentations', 'demo recordings', 'contract negotiation', 'deal closures', 'client retention', 'crm database updates', 'pipeline tracking', 'sales funnel conversion', 'quota achievements', 'business development', 'inside sales prospecting', 'corporate accounts', 'saas subscription sales', 'sales training manuals', 'revenue forecasting', 'cross-selling', 'upselling techniques', 'customer success metrics']
      },
      {
        category: 'hr',
        prefix: ['recruiting', 'talent-acquisition', 'candidate-sourcing', 'ats-lever', 'greenhouse-ats', 'lever-ats', 'workday-hr', 'taleo-ats', 'technical-recruiting', 'employee-onboarding', 'employee-retention', 'employee-engagement', 'performance-management', 'performance-reviews', 'hris-databases', 'payroll-admin', 'benefits-admin', 'labor-compliance', 'diversity-inclusion', 'conflict-resolution'],
        suffix: ['job posting campaigns', 'sourcing talent', 'ats pipeline management', 'recruitment processes', 'new hire onboarding', 'retention strategies', 'engagement surveys', 'appraisal reviews', 'hr database records', 'payroll calculations', 'benefits structures', 'regulatory compliance audits', 'diversity initiatives', 'employee relations', 'team building programs', 'workforce planning', 'training documentation', 'background checks', 'compensation benchmarks', 'exit interviews']
      },
      {
        category: 'finance',
        prefix: ['financial-analysis', 'financial-modeling', 'excel-sheets', 'financial-forecasting', 'budgeting-plans', 'cash-flow-management', 'bookkeeping-logs', 'accounting-quickbooks', 'quickbooks-finance', 'xero-accounting', 'gaap-compliance', 'ifrs-standards', 'tax-compliance', 'financial-auditing', 'corporate-finance', 'investment-banking', 'venture-capital', 'private-equity', 'dcf-valuations', 'financial-reporting'],
        suffix: ['sheet analysis', 'valuation models', 'forecast projections', 'budget allocations', 'cash flow statements', 'ledger records', 'accounting audits', 'tax filing compliance', 'banking transactions', 'deal analysis', 'due diligence reports', 'quarterly earnings', 'balance sheet audits', 'cost control auditing', 'depreciation schedules', 'amortization models', 'capital budgeting', 'risk assessment matrices', 'portfolio audits', 'finance presentations']
      }
    ];

    const generatedSkills = [...coreSkills];
    
    // We generate about 60 skills per category to reach ~800+ total skills safely and realistically.
    for (const ind of industries) {
      let count = 0;
      for (const pref of ind.prefix) {
        for (const suff of ind.suffix) {
          if (count >= 60) break;
          const canonicalName = `${pref} ${suff}`;
          // Ensure it's not a duplicate
          if (!generatedSkills.some(s => s.canonicalName === canonicalName)) {
            generatedSkills.push({
              canonicalName,
              aliases: [`${pref}-${suff}`, `${pref}_${suff}`],
              category: ind.category,
              popularityScore: 40 + Math.floor(Math.random() * 50),
              relatedSkills: [pref]
            });
            count++;
          }
        }
        if (count >= 60) break;
      }
    }

    console.log(`Generated list has ${generatedSkills.length} skills. Bulk writing to database...`);
    await SkillKnowledgeBase.insertMany(generatedSkills);
    console.log('SkillKnowledgeBase seeded successfully.');

    // Track seed creation timestamps
    const now = new Date();
    const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const hoursAgo12 = new Date(now.getTime() - 12 * 60 * 60 * 1000);
    const hoursAgo6 = new Date(now.getTime() - 6 * 60 * 60 * 1000);

    // Seed Cases
    console.log('Seeding Cases...');
    const case1 = await Case.create({
      title: 'Case Metadata Verification Audit',
      description: 'Investigating coordinated media alteration campaign involving EXIF software edits and header discrepancies circulating on social media.',
      status: 'in-progress',
      severity: 'high',
      notes: [
        { text: 'Intelligence alert received: Altered video clip uploaded on major platforms.', createdBy: investigator1._id, createdAt: twoDaysAgo },
        { text: 'Sourced original broadcast copy for differential analysis.', createdBy: investigator1._id, createdAt: oneDayAgo },
        { text: 'Image EXIF software analysis indicates Adobe Photoshop suite edits.', createdBy: investigator1._id, createdAt: hoursAgo12 }
      ],
      createdBy: admin._id,
      createdAt: twoDaysAgo,
    });
    await seedAuditLog({
      action: 'case-created',
      entityType: 'Case',
      entityId: case1._id,
      performedBy: admin._id,
      details: { title: case1.title, severity: case1.severity },
      timestamp: twoDaysAgo,
    });

    const case2 = await Case.create({
      title: 'Corporate Espionage Audio Audit',
      description: 'Reviewing audio recordings of internal executive briefings to check for voice-cloning artifacts and synthetic splicing patterns.',
      status: 'in-progress',
      severity: 'medium',
      notes: [
        { text: 'Briefing audio file recovered from suspicious network transfer node.', createdBy: investigator2._id, createdAt: oneDayAgo },
        { text: 'Pitch continuity check shows uniform spectral patterns.', createdBy: investigator2._id, createdAt: hoursAgo6 }
      ],
      createdBy: admin._id,
      createdAt: oneDayAgo,
    });
    await seedAuditLog({
      action: 'case-created',
      entityType: 'Case',
      entityId: case2._id,
      performedBy: admin._id,
      details: { title: case2.title, severity: case2.severity },
      timestamp: oneDayAgo,
    });

    const case3 = await Case.create({
      title: 'Accident Scene Authentication',
      description: 'Forensic integrity assessment of claims scene photos to verify camera source metadata matches image pixel compression noise profiles.',
      status: 'resolved',
      severity: 'low',
      notes: [
        { text: 'Submitted by Claims adjuster. Camera EXIF matches image dimensions.', createdBy: investigator1._id, createdAt: oneDayAgo },
        { text: 'ELA noise distribution is consistent across all tiles. Marked as authentic.', createdBy: investigator1._id, createdAt: hoursAgo6 }
      ],
      createdBy: investigator1._id,
      createdAt: oneDayAgo,
    });
    await seedAuditLog({
      action: 'case-created',
      entityType: 'Case',
      entityId: case3._id,
      performedBy: investigator1._id,
      details: { title: case3.title, severity: case3.severity },
      timestamp: oneDayAgo,
    });

    const case4 = await Case.create({
      title: 'Medical Record Tampering Audit',
      description: 'Assessing patient oncology PDF scan sheets to identify potential document splice edits and text generation overrides.',
      status: 'closed',
      severity: 'medium',
      notes: [
        { text: 'Hospital registry audit flagged inconsistent medical logs.', createdBy: investigator2._id, createdAt: oneDayAgo }
      ],
      createdBy: investigator2._id,
      createdAt: oneDayAgo,
    });
    await seedAuditLog({
      action: 'case-created',
      entityType: 'Case',
      entityId: case4._id,
      performedBy: investigator2._id,
      details: { title: case4.title, severity: case4.severity },
      timestamp: oneDayAgo,
    });

    console.log('Cases seeded. Seeding Evidence and Hashing...');

    // Generate SHA-256 hashes and Merkle Roots for seed items
    const generateSeedHash = (val) => crypto.createHash('sha256').update(val).digest('hex');

    // Helper for seeding content + AI analysis
    const seedEvidence = async ({
      title,
      description,
      contentType,
      derivationType,
      status,
      fileSize,
      mimeType,
      tags,
      isPublic,
      caseId,
      ownerId,
      createdAt,
      aiStats,
      verifiedBy
    }) => {
      const originalHash = generateSeedHash(title + createdAt.getTime());
      
      // Calculate mock chunks
      const chunkCount = Math.max(1, Math.ceil(fileSize / (1024 * 1024)));
      const chunkHashes = [];
      for (let i = 0; i < chunkCount; i++) {
        chunkHashes.push(generateSeedHash(originalHash + i));
      }
      const merkleRoot = buildMerkleRoot(chunkHashes);

      const content = await Content.create({
        title,
        description,
        contentType,
        derivationType,
        status,
        originalHash,
        merkleRoot,
        chunkHashes,
        fileSize,
        mimeType,
        tags,
        isPublic,
        owner: ownerId,
        verifiedBy,
        verifiedAt: status === 'verified' ? createdAt : undefined,
        createdAt,
        metadata: {
          storageUrl: `http://localhost:5000/uploads/seed-${originalHash.substring(0, 8)}.${mimeType.split('/')[1] || 'bin'}`,
          storageProvider: 'local',
          storageKey: `seed-${originalHash.substring(0, 8)}`
        }
      });

      // Link evidence to case
      if (caseId) {
        await Case.updateOne({ _id: caseId }, { $push: { evidence: content._id } });
      }

      // Seed Audit Log for content registration
      await seedAuditLog({
        action: 'content-registered',
        entityType: 'Content',
        entityId: content._id,
        performedBy: ownerId,
        details: { title: content.title, originalHash: content.originalHash, merkleRoot: content.merkleRoot },
        timestamp: createdAt,
      });

      // Seed AI Analysis Result
      if (status !== 'pending') {
        const aiAnalysis = await AIAnalysisResult.create({
          contentId: content._id,
          status: 'completed',
          metadataRiskScore: aiStats.metadataRiskScore,
          integrityVerificationScore: aiStats.integrityVerificationScore,
          verificationConfidence: aiStats.verificationConfidence,
          metadataFindings: aiStats.metadataFindings,
          analysisLogs: aiStats.analysisLogs,
          forensicReport: aiStats.forensicReport,
          processedAt: createdAt,
        });

        // Update Content scores
        await Content.updateOne(
          { _id: content._id },
          {
            authenticityScore: aiStats.authenticityScore,
            provenanceScore: aiStats.provenanceScore,
            metadataRiskScore: aiStats.metadataRiskScore,
            integrityVerificationScore: aiStats.integrityVerificationScore,
            verificationConfidence: aiStats.verificationConfidence,
          }
        );

        // Audit Log for completed verification
        await seedAuditLog({
          action: 'content-verified',
          entityType: 'Content',
          entityId: content._id,
          performedBy: verifiedBy || ownerId,
          details: { status, integrityVerificationScore: aiStats.integrityVerificationScore, metadataRiskScore: aiStats.metadataRiskScore },
          timestamp: createdAt,
        });
      }

      return content;
    };

    // 1. Evidence File: Campaign speech original (Case 1)
    const originalVideo = await seedEvidence({
      title: 'Press Briefing Original (Broadcast Copy)',
      description: 'Raw high-definition video feed sourced from network archive to establish baseline camera signature metrics.',
      contentType: 'video',
      derivationType: 'original',
      status: 'verified',
      fileSize: 45214000, // 45 MB -> 45 chunks
      mimeType: 'video/mp4',
      tags: ['broadcast', 'original', 'verification-pass'],
      isPublic: true,
      caseId: case1._id,
      ownerId: admin._id,
      createdAt: twoDaysAgo,
      verifiedBy: investigator1._id,
      aiStats: {
        metadataRiskScore: 2,
        integrityVerificationScore: 99,
        verificationConfidence: 94,
        metadataFindings: 'none',
        authenticityScore: 100,
        provenanceScore: 100,
        analysisLogs: [
          'Resolving video container metadata parameters.',
          'Format validation: standard parameters confirmed.',
          'Metadata check: no anomalous tag indicators discovered.',
          'Audio PCM WAV check: standard sample properties confirmed.',
          'Consensus: authentic file structure.'
        ],
        forensicReport: `# Integrity Summary: Press Briefing Original

## Verdict
*   **Result**: **AUTHENTIC**
*   **Integrity Verification Score**: **99%**
*   **Metadata Risk Score**: **2%**

No indicators of metadata alteration or editing suite signatures were detected. Properties align with digital recording standards.`
      }
    });

    // 2. Evidence File: Campaign speech manipulated (Case 1)
    await seedEvidence({
      title: 'Social Video Clip (tampered_campaign_speech)',
      description: 'Manipulated campaign video clip circulating on public forums, containing suspicious metadata anomalies and mismatched properties.',
      contentType: 'video',
      derivationType: 'ai-modification',
      status: 'flagged',
      fileSize: 12500000, // 12 MB
      mimeType: 'video/mp4',
      tags: ['metadata-audit', 'integrity-check', 'tampered'],
      isPublic: true,
      caseId: case1._id,
      ownerId: investigator1._id,
      createdAt: oneDayAgo,
      verifiedBy: investigator1._id,
      aiStats: {
        metadataRiskScore: 94,
        integrityVerificationScore: 13,
        verificationConfidence: 81,
        metadataFindings: 'metadata-missing',
        authenticityScore: 0,
        provenanceScore: 70, // 100 - 30 penalty
        analysisLogs: [
          'Ingesting target video container metadata.',
          'Warning: video stream properties are mismatched relative to container headers.',
          'Warning: atypical file property parameters discovered in video stream headers.',
          'Warning: core container tags are missing or corrupted.',
          'Flagged: container metadata properties altered.'
        ],
        forensicReport: `# Integrity Summary: Social Video Clip (tampered_campaign_speech)

## Verdict
*   **Result**: **FLAGGED (ALTERED METADATA)**
*   **Integrity Verification Score**: **13%**
*   **Metadata Risk Score**: **94%**

❌ **CRITICAL FLAG**: Altered metadata parameters detected. Keyframe index sequences and stream parameters contain severe structural inconsistencies.`
      }
    });

    // 3. Evidence File: CEO Synthetic/Altered briefing (Case 2)
    await seedEvidence({
      title: 'Executive Briefing Audio Clip (Recovery)',
      description: 'Audio file recovered from suspicious network node, instructing accounts to execute international funds transfer.',
      contentType: 'audio',
      derivationType: 'ai-modification',
      status: 'flagged',
      fileSize: 3200000, // 3 MB
      mimeType: 'audio/wav',
      tags: ['audio', 'espionage', 'metadata-anomaly'],
      isPublic: false,
      caseId: case2._id,
      ownerId: investigator2._id,
      createdAt: oneDayAgo,
      verifiedBy: investigator2._id,
      aiStats: {
        metadataRiskScore: 90,
        integrityVerificationScore: 14,
        verificationConfidence: 82,
        metadataFindings: 'atypical-entropy',
        authenticityScore: 0,
        provenanceScore: 70,
        analysisLogs: [
          'Analyzing audio payload. Auditing sample rate and channel count.',
          'Warning: pitch continuity is abnormally uniform, matching atypical compression patterns.',
          'Warning: Shannon byte entropy is extremely flatline/monotone (< 6.0 bits/byte).',
          'Flagged: atypical entropy compression detected.'
        ],
        forensicReport: `# Integrity Summary: Executive Briefing Audio

## Verdict
*   **Result**: **FLAGGED (ATYPICAL ENTROPY)**
*   **Integrity Verification Score**: **14%**
*   **Metadata Risk Score**: **90%**

❌ **CRITICAL FLAG**: Metadata checks detect synthetic wave properties. Low byte entropy levels indicate standard sample rates were generated artificially.`
      }
    });

    // 4. Evidence File: Accident scene tampered (Case 3)
    await seedEvidence({
      title: 'Accident Scene Photo (Claim_Attachment_01)',
      description: 'Submitted collision photo showing vehicle damage details.',
      contentType: 'image',
      derivationType: 'edit',
      status: 'flagged',
      fileSize: 1500000,
      mimeType: 'image/jpeg',
      tags: ['insurance-claim', 'tampered-photo'],
      isPublic: true,
      caseId: case3._id,
      ownerId: standardUser._id,
      createdAt: oneDayAgo,
      verifiedBy: investigator1._id,
      aiStats: {
        metadataRiskScore: 48,
        integrityVerificationScore: 44,
        verificationConfidence: 88,
        metadataFindings: 'software-edit',
        authenticityScore: 0,
        provenanceScore: 85,
        analysisLogs: [
          'Ingesting image file. Scanning EXIF tags.',
          'Warning: ELA delta compression map shows high local block variance.',
          'EXIF software tags indicate image was edited using Adobe Photoshop.',
          'Warning: Software-edit signature detected.'
        ],
        forensicReport: `# Integrity Summary: Collision Photo (Photoshop Edit)

## Verdict
*   **Result**: **FLAGGED (EDITED)**
*   **Integrity Verification Score**: **44%**
*   **Metadata Risk Score**: **48%**

⚠️ **WARNING**: Splice edit indicators detected. EXIF tags show Adobe Photoshop was used to alter image properties.`
      }
    });

    // 5. Evidence File: Accident scene raw (Case 3)
    await seedEvidence({
      title: 'Accident Scene Photo (Raw)',
      description: 'Raw scene photo sourced directly from investigator device.',
      contentType: 'image',
      derivationType: 'original',
      status: 'verified',
      fileSize: 1800000,
      mimeType: 'image/jpeg',
      tags: ['raw-scene', 'original'],
      isPublic: true,
      caseId: case3._id,
      ownerId: investigator1._id,
      createdAt: oneDayAgo,
      verifiedBy: investigator1._id,
      aiStats: {
        metadataRiskScore: 3,
        integrityVerificationScore: 99,
        verificationConfidence: 95,
        metadataFindings: 'none',
        authenticityScore: 100,
        provenanceScore: 100,
        analysisLogs: [
          'Ingesting raw image bitmap. Running metadata check.',
          'ELA results: uniform compression density across vehicle and background.',
          'EXIF headers matched camera hardware signature.',
          'Consensus: authentic photograph.'
        ],
        forensicReport: `# Integrity Summary: Raw Collision Photo

## Verdict
*   **Result**: **AUTHENTIC**
*   **Integrity Verification Score**: **99%**
*   **Metadata Risk Score**: **3%**

No indicators of metadata alteration or editing suite signatures detected.`
      }
    });

    // 6. Evidence File: Board meeting minutes (Case 4)
    await seedEvidence({
      title: 'Executive Briefing Minutes (Signed PDF)',
      description: 'Official briefing notes registered by corporate secretary.',
      contentType: 'document',
      derivationType: 'original',
      status: 'verified',
      fileSize: 850000,
      mimeType: 'application/pdf',
      tags: ['minutes', 'corporate', 'original'],
      isPublic: false,
      caseId: case4._id,
      ownerId: investigator2._id,
      createdAt: oneDayAgo,
      verifiedBy: investigator2._id,
      aiStats: {
        metadataRiskScore: 0,
        integrityVerificationScore: 100,
        verificationConfidence: 95,
        metadataFindings: 'none',
        authenticityScore: 100,
        provenanceScore: 100,
        analysisLogs: [
          'Parsing PDF document structure tags.',
          'Format validation: Standard PDF syntax verified. Producer: "Microsoft Word".',
          'Consensus: document conforms to native creation guidelines.'
        ],
        forensicReport: `# Document Verification Summary

## Verdict
*   **Result**: **AUTHENTIC**
*   **Integrity Verification Score**: **100%**

No active script blocks or revision anomalies detected in the PDF stream.`
      }
    });

    // 7. Evidence File: Standalone espionage transcript
    await seedEvidence({
      title: 'Internal Communications Log (Standalone Transcript)',
      description: 'Recovered chat logs associated with suspicious internal network activity.',
      contentType: 'text',
      derivationType: 'original',
      status: 'verified',
      fileSize: 55000,
      mimeType: 'text/plain',
      tags: ['chat-logs', 'network-activity'],
      isPublic: true,
      ownerId: investigator1._id,
      createdAt: hoursAgo12,
      verifiedBy: investigator1._id,
      aiStats: {
        metadataRiskScore: 8,
        integrityVerificationScore: 98,
        verificationConfidence: 94,
        metadataFindings: 'none',
        authenticityScore: 100,
        provenanceScore: 100,
        analysisLogs: [
          'Parsing text character metrics and lexical entropy.',
          'Consensus: Standard text syntax signatures matched.'
        ],
        forensicReport: `# Text Transcript Analysis

## Verdict
*   **Result**: **AUTHENTIC**
*   **Integrity Verification Score**: **98%**

Syntax structure and character distributions conform to expected plain text standards.`
      }
    });

    // 8. Evidence File: Pending video review (Case 1)
    await seedEvidence({
      title: 'Viral Social Interview (Candidate Speech)',
      description: 'Recently uploaded video interview displaying suspicious metadata anomalies.',
      contentType: 'video',
      derivationType: 'copy',
      status: 'pending',
      fileSize: 22000000,
      mimeType: 'video/mp4',
      tags: ['viral', 'unverified', 'elections'],
      isPublic: true,
      caseId: case1._id,
      ownerId: standardUser._id,
      createdAt: hoursAgo6,
      aiStats: {} // Pending analysis
    });

    console.log('Seeded Evidence successfully.');

    // Count records seeded
    const usersCount = await User.countDocuments();
    const casesCount = await Case.countDocuments();
    const contentCount = await Content.countDocuments();
    const findingsCount = await AIAnalysisResult.countDocuments();
    const logsCount = await AuditLog.countDocuments();

    console.log('=========================================');
    console.log('SEEDING SUMMARY');
    console.log('=========================================');
    console.log(`- Enrolled Users: ${usersCount}`);
    console.log(`- Cases Created: ${casesCount}`);
    console.log(`- Evidence Files: ${contentCount}`);
    console.log(`- AI Analysis Results: ${findingsCount}`);
    console.log(`- Chained Cryptographic Logs: ${logsCount}`);
    console.log('=========================================');

    // Run verification of audit logs chain integrity
    console.log('Verifying seeded audit chain integrity...');
    const { verifyAuditChain: auditVerify } = require('../controllers/auditController');
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          console.log(`Chain Integrity Verification Status (${code}):`, data.verified ? '✅ VALID CHAIN' : '❌ COMPROMISED CHAIN');
          if (!data.verified) {
             console.error('Compromised logs:', data.compromisedLogs);
          }
        }
      })
    };
    await auditVerify({}, mockRes, (err) => {
      console.error('Verify Audit Chain Middleware Error:', err);
    });

    mongoose.connection.close();
    console.log('Seed Complete. Connection closed.');
  } catch (err) {
    console.error('Seeding process critical failure:', err);
    process.exit(1);
  }
}

runSeed();
