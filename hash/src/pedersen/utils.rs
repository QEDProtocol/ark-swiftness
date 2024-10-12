use crate::pedersen::constants::{P0, P1, P2, P3, P4};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveConfig;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::curves::short_weierstrass::ProjectiveVar;
use swiftness_field::{Fp, SimpleField};
use swiftness_utils::curve::StarkwareCurve;

/*
   Example of code with macro expansion
   ```rust
       fn get_a_p0_proj() -> ProjectiveVar<Self, FpVar<<Self as CurveConfig>::BaseField>>
   where
       Self: SWCurveConfig,
       Self::BaseField: PrimeField + SimpleField,
       <Self::BaseField as Field>::BasePrimeField: SimpleField,
       FpVar<Self::BaseField>: FieldVar<Self::BaseField, <Self::BaseField as Field>::BasePrimeField> + SimpleField,
   ;
   ```
*/
macro_rules! define_projective_fn_header {
    ($fn_name:ident) => {
        fn $fn_name() -> ProjectiveVar<Self, FpVar<<Self as CurveConfig>::BaseField>>
        where
            Self: SWCurveConfig,
            Self::BaseField: PrimeField + SimpleField,
            <Self::BaseField as Field>::BasePrimeField: SimpleField,
            FpVar<Self::BaseField>:
                FieldVar<Self::BaseField, <Self::BaseField as Field>::BasePrimeField> + SimpleField;
    };
}

pub trait CurveProjectiveProvider: SWCurveConfig {
    define_projective_fn_header!(get_a_p0_proj);
    define_projective_fn_header!(get_a_p1_proj);
    define_projective_fn_header!(get_a_p2_proj);
    define_projective_fn_header!(get_b_p1_proj);
    define_projective_fn_header!(get_b_p2_proj);
}

/*
   Example of code with macro expansion:
   ```rust
   thread_local! {
   static A_P0_PROJ: ProjectiveVar<StarkwareCurve, FpVar<Fp>> =
       ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new(
           FpVar::Constant(SimpleField::from_felt(P0.x)),
           FpVar::Constant(SimpleField::from_felt(P0.y)),
           FpVar::Constant(SimpleField::one()),
       );

       }
    ```
*/
macro_rules! define_projective_vars {
    ( $( $name:ident, $px:expr, $py:expr ),* ) => {
        thread_local! {
            $(
                static $name: ProjectiveVar<StarkwareCurve, FpVar<Fp>> = {
                    ProjectiveVar::<StarkwareCurve, FpVar<Fp>>::new(
                        FpVar::Constant(SimpleField::from_felt($px)),
                        FpVar::Constant(SimpleField::from_felt($py)),
                        FpVar::Constant(SimpleField::one()),
                    )
                };
            )*
        }
    };
}
define_projective_vars!(
    A_P0_PROJ, P0.x, P0.y, A_P1_PROJ, P1.x, P1.y, A_P2_PROJ, P2.x, P2.y, B_P1_PROJ, P3.x, P3.y,
    B_P2_PROJ, P4.x, P4.y
);
/*
   Example of code with macro expansion:
   ```rust
       fn get_a_p1_proj() -> ProjectiveVar<Self, FpVar<<Self as CurveConfig>::BaseField>>
   where
       Self: SWCurveConfig,
       Self::BaseField: PrimeField + SimpleField,
       <Self::BaseField as Field>::BasePrimeField: SimpleField,
       FpVar<Self::BaseField>: FieldVar<Self::BaseField, <Self::BaseField as Field>::BasePrimeField> + SimpleField
   {
       A_P1_PROJ.with(|a| a.clone())
   }
   ```
*/
macro_rules! define_projective_fn {
    ($fn_name:ident, $proj:ident) => {
        fn $fn_name() -> ProjectiveVar<Self, FpVar<Self::BaseField>>
        where
            Self: SWCurveConfig,
            Self::BaseField: PrimeField + SimpleField,
            <Self::BaseField as Field>::BasePrimeField: SimpleField,
            FpVar<Self::BaseField>:
                FieldVar<Self::BaseField, <Self::BaseField as Field>::BasePrimeField> + SimpleField,
        {
            $proj.with(|a| a.clone())
        }
    };
}
impl CurveProjectiveProvider for StarkwareCurve {
    define_projective_fn!(get_a_p0_proj, A_P0_PROJ);
    define_projective_fn!(get_a_p1_proj, A_P1_PROJ);
    define_projective_fn!(get_a_p2_proj, A_P2_PROJ);
    define_projective_fn!(get_b_p1_proj, B_P1_PROJ);
    define_projective_fn!(get_b_p2_proj, B_P2_PROJ);
}

/*
    Example of code with macro expansion:
    ```rust


pub fn get_a_p0_proj_outer<P: SWCurveConfig + CurveProjectiveProvider>() -> ProjectiveVar::<P, FpVar<P::BaseField>>
where P::BaseField: PrimeField + SimpleField,
      <P::BaseField as Field>::BasePrimeField: SimpleField,
      FpVar<P::BaseField>: FieldVar<P::BaseField,
          <P::BaseField as Field>::BasePrimeField> + SimpleField,
{
    CurveProjectiveProvider::get_a_p0_proj()
}

```
 */
macro_rules! define_proj_outer_fn {
    ($fn_name:ident, $inner_fn:ident) => {
        pub fn $fn_name<P: SWCurveConfig + CurveProjectiveProvider>(
        ) -> ProjectiveVar<P, FpVar<P::BaseField>>
        where
            P::BaseField: PrimeField + SimpleField,
            <P::BaseField as Field>::BasePrimeField: SimpleField,
            FpVar<P::BaseField>:
                FieldVar<P::BaseField, <P::BaseField as Field>::BasePrimeField> + SimpleField,
        {
            CurveProjectiveProvider::$inner_fn()
        }
    };
}
define_proj_outer_fn!(get_a_p0_proj_outer, get_a_p0_proj);
define_proj_outer_fn!(get_a_p1_proj_outer, get_a_p1_proj);
define_proj_outer_fn!(get_a_p2_proj_outer, get_a_p2_proj);
define_proj_outer_fn!(get_b_p1_proj_outer, get_b_p1_proj);
define_proj_outer_fn!(get_b_p2_proj_outer, get_b_p2_proj);
