#![allow(deprecated)]
use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    program_error::ProgramError,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    system_program,
};
use zk_fresh_program::*;

fn field(n: u64) -> [u8; 32] {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    b
}
fn error(e: FreshError) -> ProgramError {
    ProgramError::Custom(e as u32)
}
struct FixedClock;
impl SyscallStubs for FixedClock {
    fn sol_get_clock_sysvar(&self, address: *mut u8) -> u64 {
        unsafe {
            std::ptr::write_unaligned(
                address.cast::<Clock>(),
                Clock {
                    unix_timestamp: 1200,
                    ..Clock::default()
                },
            )
        };
        0
    }
}
#[test]
fn entrypoint_rejects_bad_bindings_and_authority_without_writes() {
    let previous = set_syscall_stubs(Box::new(FixedClock));
    let program = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let seed = [7; 32];
    let (registry_key, bump) =
        Pubkey::find_program_address(&[b"registry", authority.as_ref(), &seed], &program);
    let registry = Registry::new(authority, seed, field(8), field(1), 0, 300, 1000, bump).unwrap();
    let action = [9; 32];
    let recipient = [10; 32];
    let (receipt_key, _) =
        Pubkey::find_program_address(&[b"receipt", registry_key.as_ref(), &action], &program);
    let payer_key = Pubkey::new_unique();
    let system = system_program::id();
    let mut payer_lamports = 100000000;
    let mut registry_lamports = 100000000;
    let mut receipt_lamports = 1;
    let mut system_lamports = 0;
    let mut payer_data = [];
    let mut registry_data = registry.encode();
    let original = registry_data.clone();
    let mut receipt_data = [];
    let mut system_data = [];
    {
        let payer = AccountInfo::new(
            &payer_key,
            true,
            true,
            &mut payer_lamports,
            &mut payer_data,
            &system,
            false,
            0,
        );
        let account = AccountInfo::new(
            &registry_key,
            false,
            true,
            &mut registry_lamports,
            &mut registry_data,
            &program,
            false,
            0,
        );
        let receipt = AccountInfo::new(
            &receipt_key,
            false,
            true,
            &mut receipt_lamports,
            &mut receipt_data,
            &system,
            false,
            0,
        );
        let system_account = AccountInfo::new(
            &system,
            false,
            false,
            &mut system_lamports,
            &mut system_data,
            &system,
            true,
            0,
        );
        let mut update = vec![1];
        update.extend(field(2));
        update.extend(0u64.to_le_bytes());
        assert_eq!(
            process_instruction(&program, &[payer.clone(), account.clone()], &update),
            Err(error(FreshError::Unauthorized))
        );
        assert_eq!(&*account.try_borrow_data().unwrap(), &original);
        let digest = action_digest(&program, &registry_key, &recipient, &action);
        let mut inputs = [field(1), field(8), field(1000), field(1300), digest];
        let authorization = |inputs: [[u8; 32]; 5]| {
            let mut b = vec![2];
            for i in inputs {
                b.extend(i)
            }
            b.extend([0; 256]);
            b.extend(action);
            b.extend(recipient);
            b
        };
        let accounts = [
            payer.clone(),
            account.clone(),
            receipt.clone(),
            system_account,
        ];
        inputs[1] = field(7);
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::IssuerMismatch))
        );
        inputs[1] = field(8);
        inputs[4] = field(99);
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::ActionMismatch))
        );
        inputs[4] = digest;
        inputs[2] = field(1201);
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::NotYetValid))
        );
        inputs[2] = field(1000);
        inputs[3] = field(1199);
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::CredentialExpired))
        );
        inputs[3] = field(1300);
        inputs[0] = field(2);
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::RootNotAccepted))
        );
        inputs[0] = field(1);
        inputs[4] = FIELD_MODULUS;
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(FreshError::NonCanonicalField))
        );
        inputs[4] = digest;
        let expected = if generated_vk::VK_ENABLED {
            FreshError::InvalidProof
        } else {
            FreshError::VerificationKeyDisabled
        };
        assert_eq!(
            process_instruction(&program, &accounts, &authorization(inputs)),
            Err(error(expected))
        );
        assert_eq!(receipt.lamports(), 1);
        assert_eq!(receipt.data_len(), 0);
        assert_eq!(receipt.owner, &system);
        assert_eq!(&*account.try_borrow_data().unwrap(), &original);
        let mut unsigned_lamports = 0;
        let mut unsigned_data = [];
        let unsigned = AccountInfo::new(
            &authority,
            false,
            true,
            &mut unsigned_lamports,
            &mut unsigned_data,
            &system,
            false,
            0,
        );
        assert_eq!(
            process_instruction(&program, &[unsigned, account.clone()], &update),
            Err(error(FreshError::MissingSignature))
        );
        let mut authority_lamports = 0;
        let mut authority_data = [];
        let authorized = AccountInfo::new(
            &authority,
            true,
            false,
            &mut authority_lamports,
            &mut authority_data,
            &system,
            false,
            0,
        );
        let mut readonly = account.clone();
        readonly.is_writable = false;
        assert_eq!(
            process_instruction(&program, &[authorized.clone(), readonly], &update),
            Err(error(FreshError::NotWritable))
        );
        let mut wrong_owner = account.clone();
        wrong_owner.owner = &system;
        assert_eq!(
            process_instruction(&program, &[authorized.clone(), wrong_owner], &update),
            Err(error(FreshError::InvalidOwner))
        );
        let wrong_key = Pubkey::new_unique();
        let mut wrong_pda = account.clone();
        wrong_pda.key = &wrong_key;
        assert_eq!(
            process_instruction(&program, &[authorized.clone(), wrong_pda], &update),
            Err(error(FreshError::InvalidAccount))
        );
        let mut used_receipt = receipt.clone();
        used_receipt.owner = &program;
        assert_eq!(
            process_instruction(
                &program,
                &[payer, account.clone(), used_receipt, accounts[3].clone()],
                &authorization(inputs)
            ),
            Err(error(FreshError::AlreadyUsed))
        );
        process_instruction(&program, &[authorized.clone(), account.clone()], &update).unwrap();
        let advanced = account.try_borrow_data().unwrap().to_vec();
        assert_eq!(Registry::decode(&advanced).unwrap().current_version, 1);
        assert_eq!(
            Registry::decode(&advanced)
                .unwrap()
                .accepted_root(&field(1), 1200),
            Err(FreshError::RootNotAccepted)
        );
        assert_eq!(
            process_instruction(&program, &[authorized, account.clone()], &update),
            Err(error(FreshError::InvalidVersion))
        );
        assert_eq!(&*account.try_borrow_data().unwrap(), &advanced);
    }
    set_syscall_stubs(previous);
}
