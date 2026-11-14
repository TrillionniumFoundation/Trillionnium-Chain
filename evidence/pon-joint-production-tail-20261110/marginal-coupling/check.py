"""Exact declared finite marginals. No native law or resource bound is certified."""
from fractions import Fraction as F

def marginal(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        raise ValueError('MARGINAL_SIZE')
    result=[]
    for row in rows:
        if not isinstance(row,tuple) or len(row)!=2:
            raise ValueError('ROW')
        value,p=row
        if type(value) is not F or type(p) is not F or value<=0 or not 0<p<=1:
            raise ValueError('EXACT_POSITIVE_RATIONAL_REQUIRED')
        if max(value.numerator.bit_length(),value.denominator.bit_length(),p.numerator.bit_length(),p.denominator.bit_length())>256:
            raise ValueError('INPUT_BITS')
        result.append((value,p))
    if sum(p for _,p in result)!=1: raise ValueError('TOTAL_MASS')
    return sorted(result)

def product_extrema(left,right):
    """Return attainable (minimum, maximum) over every coupling of these marginals."""
    left=marginal(left);right=marginal(right)
    def couple(rows):
        i=j=0;lp=left[0][1];rp=rows[0][1];total=F(0);plan=[]
        while i<len(left) and j<len(rows):
            mass=min(lp,rp)
            total+=mass*left[i][0]*rows[j][0]
            if max(total.numerator.bit_length(),total.denominator.bit_length())>65536:
                raise ValueError('ARITHMETIC_LIMIT')
            plan.append((left[i][0],rows[j][0],mass))
            lp-=mass;rp-=mass
            if lp==0:
                i+=1
                if i<len(left):lp=left[i][1]
            if rp==0:
                j+=1
                if j<len(rows):rp=rows[j][1]
        assert i==len(left) and j==len(rows)
        return total,plan
    lo,loplan=couple(list(reversed(right)));hi,hiplan=couple(right)
    return {'lower':lo,'upper':hi,'lower_plan':loplan,'upper_plan':hiplan,
            'native_failure_bound':None,'production_activation':False}

if __name__=='__main__':
    import json
    left=[(F(1,2),F(1,2)),(F(3,2),F(1,2))];right=[(F(9,10),F(1))]
    r=product_extrema(left,right)
    cs_square=sum(p*v*v for v,p in left)*sum(p*v*v for v,p in right)
    print(json.dumps({'scope':'declared-finite-marginal-laws-only','worst_coupling':str(r['upper']),
        'cs_squared':str(cs_square),'worst_coupling_passes':r['upper']<=1,
        'cs_passes':cs_square<=1,'native_failure_bound':None,'production_activation':False},sort_keys=True))
