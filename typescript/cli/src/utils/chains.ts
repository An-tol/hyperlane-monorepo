import { Separator, confirm } from '@inquirer/prompts';
import select from '@inquirer/select';
import chalk from 'chalk';

import { ChainMap, ChainMetadata } from '@hyperlane-xyz/sdk';
import { toTitleCase } from '@hyperlane-xyz/utils';

import { log } from '../logger.js';

import { calculatePageSize } from './cli-options.js';
import { SearchableCheckboxChoice, searchableCheckBox } from './input.js';

// A special value marker to indicate user selected
// a new chain in the list
const NEW_CHAIN_MARKER = '__new__';

export async function runSingleChainSelectionStep(
  chainMetadata: ChainMap<ChainMetadata>,
  message = 'Select chain',
) {
  const networkType = await selectNetworkType();
  const { choices, networkTypeSeparator } = getChainChoices(
    chainMetadata,
    networkType,
  );
  const chain = (await select({
    message,
    choices: [networkTypeSeparator, ...choices],
    pageSize: calculatePageSize(2),
  })) as string;
  handleNewChain([chain]);
  return chain;
}

type RunMultiChainSelectionStepOptions = {
  /**
   * The metadata of the chains that will be displayed to the user
   */
  chainMetadata: ChainMap<ChainMetadata>;

  /**
   * The message to display to the user
   *
   * @default 'Select chains'
   */
  message?: string;

  /**
   * The minimum number of chains that must be selected
   *
   * @default 0
   */
  requireNumber?: number;

  /**
   * Whether to ask for confirmation after the selection
   *
   * @default false
   */
  requiresConfirmation?: boolean;

  /**
   * The network type to filter the chains by
   *
   * @default undefined
   */
  networkType?: 'mainnet' | 'testnet';
};

export async function runMultiChainSelectionStep({
  chainMetadata,
  message = 'Select chains',
  requireNumber = 0,
  requiresConfirmation = false,
  networkType = undefined,
}: RunMultiChainSelectionStepOptions) {
  const selectedNetworkType = networkType ?? (await selectNetworkType());
  const { choices, networkTypeSeparator } = getChainChoices(
    chainMetadata,
    selectedNetworkType,
  );

  let currentChoiceSelection = new Set();
  while (true) {
    const chains = await searchableCheckBox({
      message,
      selectableOptionsSeparator: networkTypeSeparator,
      choices: choices.map((choice) =>
        currentChoiceSelection.has(choice.name)
          ? { ...choice, checked: true }
          : choice,
      ),
      instructions: `Use TAB key to select at least ${requireNumber} chains, then press ENTER to proceed. Type to search for a specific chain.`,
      theme: {
        style: {
          // The leading space is needed because the help tip will be tightly close to the message header
          helpTip: (text: string) => ` ${chalk.bgYellow(text)}`,
        },
        helpMode: 'always',
      },
      pageSize: calculatePageSize(2),
      validate: (answer): string | boolean => {
        if (answer.length < requireNumber) {
          return `Please select at least ${requireNumber} chains`;
        }

        return true;
      },
    });

    handleNewChain(chains);

    const confirmed = requiresConfirmation
      ? await confirm({
          message: `Is this chain selection correct?: ${chalk.cyan(
            chains.join(', '),
          )}`,
        })
      : true;
    if (!confirmed) {
      currentChoiceSelection = new Set(chains);
      continue;
    }

    return chains;
  }
}

async function selectNetworkType() {
  const networkType = await select({
    message: 'Select network type',
    choices: [
      { name: 'Mainnet', value: 'mainnet' },
      { name: 'Testnet', value: 'testnet' },
    ],
  });
  return networkType as 'mainnet' | 'testnet';
}

function getChainChoices(
  chainMetadata: ChainMap<ChainMetadata>,
  networkType: 'mainnet' | 'testnet',
) {
  const chainsToChoices = (chains: ChainMetadata[]) =>
    chains.map((c) => ({ name: c.name, value: c.name }));

  const chains = Object.values(chainMetadata);
  const filteredChains = chains.filter((c) =>
    networkType === 'mainnet' ? !c.isTestnet : !!c.isTestnet,
  );
  const choices: SearchableCheckboxChoice<string>[] = [
    { name: '(New custom chain)', value: NEW_CHAIN_MARKER },
    ...chainsToChoices(filteredChains),
  ];

  return {
    choices,
    networkTypeSeparator: new Separator(
      `--${toTitleCase(networkType)} Chains--`,
    ),
  };
}

function handleNewChain(chainNames: string[]) {
  if (chainNames.includes(NEW_CHAIN_MARKER)) {
    log(
      chalk.blue('Use the'),
      chalk.magentaBright('hyperlane registry init'),
      chalk.blue('command to create new configs'),
    );
    process.exit(0);
  }
}
