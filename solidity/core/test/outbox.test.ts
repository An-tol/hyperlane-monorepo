import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { expect } from 'chai';
import { ethers } from 'hardhat';

import { types, utils } from '@abacus-network/utils';

import { Outbox, Outbox__factory } from '../types';

const localDomain = 1000;
const destDomain = 2000;

describe('Outbox', async () => {
  let outbox: Outbox, signer: SignerWithAddress, recipient: SignerWithAddress;

  before(async () => {
    [signer, recipient] = await ethers.getSigners();
  });

  beforeEach(async () => {
    // redeploy the outbox before each test run
    const outboxFactory = new Outbox__factory(signer);
    outbox = await outboxFactory.deploy(localDomain);
    // The ValidatorManager is unused in these tests *but* needs to be a
    // contract.
    await outbox.initialize(outbox.address);
  });

  it('Cannot be initialized twice', async () => {
    await expect(outbox.initialize(outbox.address)).to.be.revertedWith(
      'Initializable: contract is already initialized',
    );
  });

  it('ValidatorManager can fail', async () => {
    await outbox.setValidatorManager(signer.address);
    await outbox.fail();
    expect(await outbox.state()).to.equal(types.AbacusState.FAILED);

    const message = ethers.utils.formatBytes32String('message');
    await expect(
      outbox.dispatch(
        destDomain,
        utils.addressToBytes32(recipient.address),
        message,
      ),
    ).to.be.revertedWith('failed state');
  });

  it('Non ValidatorManager cannot fail', async () => {
    await expect(outbox.connect(recipient).fail()).to.be.revertedWith(
      '!validatorManager',
    );
  });

  describe('#dispatch', () => {
    const testMessageValues = async () => {
      const message = ethers.utils.formatBytes32String('message');

      const abacusMessage = utils.formatMessage(
        localDomain,
        signer.address,
        destDomain,
        recipient.address,
        message,
      );
      const leafIndex = await outbox.tree();
      const hash = utils.messageHash(abacusMessage, leafIndex.toNumber());

      return {
        message,
        destDomain,
        abacusMessage,
        hash,
        leafIndex,
      };
    };

    it('Does not dispatch too large messages', async () => {
      const message = `0x${Buffer.alloc(3000).toString('hex')}`;
      await expect(
        outbox.dispatch(
          destDomain,
          utils.addressToBytes32(recipient.address),
          message,
        ),
      ).to.be.revertedWith('msg too long');
    });

    it('Dispatches a message', async () => {
      const { message, destDomain, abacusMessage, hash, leafIndex } =
        await testMessageValues();

      // Send message with signer address as msg.sender
      await expect(
        outbox
          .connect(signer)
          .dispatch(
            destDomain,
            utils.addressToBytes32(recipient.address),
            message,
          ),
      )
        .to.emit(outbox, 'Dispatch')
        .withArgs(hash, leafIndex, destDomain, abacusMessage);
    });

    it('Returns the leaf index of the dispatched message', async () => {
      const { message, leafIndex } = await testMessageValues();

      const dispatchLeafIndex = await outbox
        .connect(signer)
        .callStatic.dispatch(
          destDomain,
          utils.addressToBytes32(recipient.address),
          message,
        );

      expect(dispatchLeafIndex).equals(leafIndex);
    });
  });
});
