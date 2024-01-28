#[cfg(test)]
mod tests {
    use crate::curv::elliptic::curves::traits::ECScalar;
    use crate::kms::rotation::two_party::party1::Rotation1;
    use crate::kms::rotation::two_party::party2::Rotation2;

    #[test]
    fn test_coin_flip() {
        //coin flip:
        let (party1_first_message, m1, r1) = Rotation1::key_rotate_first_message();
        let party2_first_message = Rotation2::key_rotate_first_message(&party1_first_message);
        let (party1_second_message, random1) =
            Rotation1::key_rotate_second_message(&party2_first_message, &m1, &r1);
        let random2 = Rotation2::key_rotate_second_message(
            &party1_second_message,
            &party2_first_message,
            &party1_first_message,
        );
        assert_eq!(
            random1.rotation.get_element(),
            random2.rotation.get_element()
        );
    }
}
