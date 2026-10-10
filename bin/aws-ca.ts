#!/usr/bin/env node
import { App } from 'aws-cdk-lib/core';
import { AwsCaStack } from '../lib/aws-ca-stack';

const app = new App();
new AwsCaStack(app, 'AwsCaStack');
