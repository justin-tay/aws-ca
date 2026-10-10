import { InMemoryCaRepository } from '../../src/repo';
import { repositoryContract } from './contract';

repositoryContract('InMemoryCaRepository', () => Promise.resolve({ repository: new InMemoryCaRepository() }));
