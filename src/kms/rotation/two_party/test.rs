#[cfg(test)]
mod tests {
    use crate::curv::elliptic::curves::traits::ECScalar;
    use crate::kms::rotation::two_party::party1::RotationParty1;
    use crate::kms::rotation::two_party::party2::RotationParty2;

    #[test]
    fn test_coin_flip() {
        //coin flip:
        let party1_first_msg = RotationParty1::key_rotate_first_message();
        let party2_first_msg = RotationParty2::key_rotate_first_message(&party1_first_msg.coin_flip);
        let party1_second_mgs =
            RotationParty1::key_rotate_second_message(&party2_first_msg.coin_flip, &party1_first_msg.seed, &party1_first_msg.blinding);
        let party2_rotation = RotationParty2::key_rotate_second_message(
            &party1_second_mgs.coin_flip,
            &party2_first_msg.coin_flip,
            &party1_first_msg.coin_flip,
        );
        assert_eq!(
            party1_second_mgs.rotation.scalar.get_element(),
            party2_rotation.scalar.get_element()
        );
    }
}