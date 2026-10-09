/* Test-only C model of R5900 whole-row PMULTUW helper.
 * Used by run-p256-host.sh to exercise real P-256 fixed-prime REDC.
 * This MUST NEVER be linked into a real EE binary.
 */
#include <stddef.h>
#include <stdint.h>
uint32_t ossl_ee_bn_muladd_row_mmi(uint32_t *t,const uint32_t *a,
                                    uint32_t multiplier,size_t num)
{
    uint64_t carry=0,z;
    size_t j;
    for(j=0;j<num;++j) {
        z=(uint64_t)t[j]+(uint64_t)a[j]*multiplier+carry;
        t[j]=(uint32_t)z;
        carry=z>>32;
    }
    return (uint32_t)carry;
}
