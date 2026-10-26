#!/usr/bin/env python3
"""Exact native functional fixtures and adversarial mutations; never a benchmark.

All bytes were emitted by the real new native example. Every positive and
negative replay uses the canonical scalar oracle. The compact archive shares
compression across raw logs; independent SHA-256 values bind every original.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import lzma
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import w1_miner_budget_reader as reader

NATIVE_FUNCTIONAL_ORIGIN = {'baseline_head': '4081bf6f397b74cf4f928e845259a18d68211181', 'status': 'exact unfrozen native functional stdout; no performance ratios', 'binary_sha256': '1a8ad8b5680aa6b716c61c8cd3d5da31f3e01a51af3898a84e9e517fe5dd6dea', 'rust_source_sha256': {'trillionnium/crates/trnm-pon-node/examples/pon_w1_miner_budget_research.rs': '9e9bbf9b68fadcca8b8d7ea3c0c7ce12677d18402e7c09fac1dec6959222d5d1', 'trillionnium/crates/trnm-pon-node/examples/support/w1_miner_budget.rs': 'd376fa48c5e60932c7d3cc4720919d60a7663d3ab12543d2bd5ae04212f01382'}}
FIXTURES = {'setup-zero': {'offset': 0, 'bytes': 5360, 'sha256': 'cae75e816c9d3c13715abf0a971b9f678a47042d459c3e74c9189a5077b8d236', 'args': ['--setup-budget-ns', '0', '--miner-budget-ns', '0', '--max-attempts', '4']}, 'miner-zero': {'offset': 5360, 'bytes': 379650, 'sha256': '846e3287bce4170800a86bca5597fdec1036b0dc1f4b80b0be235b3e4baf35c6', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '0', '--max-attempts', '4']}, 'maintenance-cap': {'offset': 385010, 'bytes': 795671, 'sha256': '022b56ed9b0a08c7cde6f724b3439bc2fcfedb6f1779e42ba8fc7818e1119823', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '128000000', '--max-attempts', '4', '--policy', 'maintenance-only', '--arm', 'integer-paired-general', '--cache', 'hot', '--seed', '3101']}, 'zero-paired-cold': {'offset': 1180681, 'bytes': 972381, 'sha256': '39385a597941aaa68ceb25f1b1319a2d2adf370f338df3ba8876a8c647b28cf2', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '128000000', '--max-attempts', '4', '--policy', 'zero-only', '--arm', 'structure-paired', '--cache', 'cold', '--seed', '3102']}, 'screen-four-specialized': {'offset': 2153062, 'bytes': 2958107, 'sha256': '8e92816100490b049d1b43823ef1d4acc4b8a8c4a8b5e2443ddb96ce0100ea29', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '128000000', '--max-attempts', '4', '--parents', '4', '--policy', 'paid-noise-screen', '--screen-width', '2', '--arm', 'structure-specialized', '--cache', 'hot', '--seed', '3102']}, 'budget-cold': {'offset': 5111169, 'bytes': 1217381, 'sha256': '34ea0880c3974f40915943f4b170da6dab16027e51cead71d7597ff24ca366f3', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '8000000', '--max-attempts', '4096', '--arm', 'integer-paired-general', '--cache', 'cold', '--seed', '3101']}, 'miner-late-proof': {'offset': 6328550, 'bytes': 483657, 'sha256': '0e5b3584141db9dbf13b3ad6b91962f2ec7b4ce86e6831267203cff42967154a', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '100000', '--max-attempts', '4096', '--arm', 'prepared-generic', '--cache', 'hot', '--seed', '3101']}, 'setup-atomic-tail': {'offset': 6812207, 'bytes': 144899, 'sha256': '8063dd8e2bfb656bbe8464487871f360a1296cc4b686ff4077fdde350e9d19a2', 'args': ['--setup-budget-ns', '1000000', '--miner-budget-ns', '128000000', '--max-attempts', '4', '--policy', 'zero-only']}, 'setup-registration-tail': {'offset': 6957106, 'bytes': 350577, 'sha256': 'e18b675e7ac4856764b9853a3493860d5208b0e3e0282ebdd16394d6ac4264e9', 'args': ['--setup-budget-ns', '14000000', '--miner-budget-ns', '128000000', '--max-attempts', '4', '--policy', 'zero-only']}, 'four-ancestor-all': {'offset': 7307683, 'bytes': 3307023, 'sha256': '1b6fdaa1dc751c825033cf8f4cec898c9fa3a8b48ef3eecc90367c1f49107bee', 'args': ['--setup-budget-ns', '1000000000', '--miner-budget-ns', '128000000', '--max-attempts', '8', '--parents', '4', '--policy', 'round-robin', '--arm', 'structure-paired', '--cache', 'hot', '--seed', '3102']}}
PACK_SHA256 = 'b0f441242fceff16fc3910493f2d2b9013338c3454130bec85fd61eb52964e7e'
PACK_LZMA85 = (
    '{Wp48S^xk9=GL@E0stWa761SMbT8$j|Nqfoa$NvDh=@m%kIKe}77r~Z)Mu7m>Fc*aLP+pd^|vgM#X9a8ruP!rKN3Sy$i)75T+QBf'
    'M+Qek(3rQFqTzP0o2`okEy{iCU_feCRkCJ!mFFcI5lWbIEnOx1vj3MPu?j8F3sGoLD9ic{jGtW`Jj5J?J1asTvAw6CTQSYm8zBqK'
    '<H=U&Uj9P`O%h@9T9`{v#_e@+ujC?*HC|S00e_Vd5fiZ_wc+LGwr1XjI9C?zSbgR{R9S1|?GIF9ftrN6cHj58B4Pc?#T`lqRJLpg'
    'tGu)Uyo`8}1*?lGQ|_)h2EnXXxWqT0do^0ntWr9YKmrQxQ|NDK+y&0)01#y@-#eY+yk)8O+*tbl7}ho%e#rlb*(Vuj+CkAsN7*Hh'
    'PHAktt;)H!*bb(S?=MR8A95zwSzlyL^We@j;r3Fu7dwO&c61V>gSdDkJ1%W?El##S35z|C-jvoby>9EgS<}Mk9R%+U@n7(EA*eS6'
    'nM2HwmE4oiw`GQj2EePFk$R-F?uCA))YXz(yx|=dBJd7QW73T6O!)<i2X!XginK(Wa;fc~!(N1C<BHA&Vsr|Gss?r@Y<K*0zO|X*'
    'NmVI6;G7$*p;rEC!kmWCP-qi(WXASZ%ZRpOb?cZ(A}@e6oCtzZ;6v|C6;|Wv=7<gih9QnEp9MfUbP99#C6f}m`M$ESAsHVZT|Htn'
    'G1Z{}O$j0PQ&jS$U?Mh4xq6IiK5fSDGkU4_S#_9{{)e3Fj?)T?rrzng3b>L>647h77D}1}6)fuz$EoXs#!j2$9l@?$Pf`O5M88N='
    '=p=L-M+wn4otL)9^$Gp7^Vy3b>xQi$Y4QT=?|??1ITA2l2@|mbuy!xI1WTsYJjI?fIL-^A>K8P)v#g6NO4)j=by&5gxu@iW0K@9_'
    'ZqcRCw4!bC%_8YlLsNu`iX!8yYuQdNn<RuF8JX{&wRptBN7xtXj>|?DryXKUJ_58l;H(U0wYJR-POKi-Oh~0zwB1XfSwltoCqo_E'
    '@D<{2e9F9a1O=fZMS|=!HmQFbr?>(`tNlft*LpHGNw;eLz1E;^^T3fp!Cpe<V54buuI-qx5lZaavgJ+=4=uYKCVpb_a7~9EDwCr*'
    'H3Vg`K?&~ZrMBqFR6Z|jYtQxOOdWaqZi5ddSDf6a_yq?>_v1x`5ZH;~($mc-urG9JF<z^n!P*5MTmt9#VCzEEe;4<r$!$?^zUuD4'
    'Ftj6VM{1R|#FY%ZpdXS}MJkY_UkA6-Duew9_+AYkH~Yj_$il576gD|?HtKx1RD0)<uHa5Vx@}xL3Mw?|$2t+W^A5*aPTddlf0eu!'
    '5$tP^7xQe!BB>do2->z*J7Xzw!q`K-rC*nnKf=OV#J-ZfbcIjVQl&@!hC%%$AQ+?IMY_3BC>XpQfQhxO_tzp7KaHAyF#+$&llaXL'
    'CRju5w|7fi)>7bk98fQ={(c%Y_oT@g7mL?IVU#DB^I(IMk5G<6MW)XJds$tKNAX{%v9vGZv`Ti7i5W0EI~mfY#6)gi^FOKQhLq(P'
    'icD!tZE*MF_=$QiU7f09x>A+XWu`}-SPhA5cY<tWv~C-tk=*ezfRT`lQ|=q<($j(Q5hd1-+Rp5zLdAB|FDo(<i{DkA#jSxsG;^4d'
    'uW>`8Py6wi8J37y9?h$<Zk-Q4>UV!SGqjU@^eTUoHKqiXx&qOP8Se&)A*cYKt5Jy*kkY`kz#>Xo&2c)g25avsNZk{|j!LH8>BPL7'
    'TWX>@<wH$n>6L?oU0x9lF2D7s(_0(%$gH=BMlubhaH_#z!RPAfiZrj5cgmP}a%+>L)zYi3!p`ojiAf}}A~hT*RnxjhJjA`ZEn5K5'
    '_$CY46DAseRj=2WEgT>ZvB~vmPbXNjxz%4kdUfg1I9DB8&xm}wTx}xyHEKiJjf*29h~NQcQnBua`=U?wiuTxxiz+4I`je%m{&}kA'
    'ri)II#TPyEx9kTxh65S%n%`&1s5(ketjq5~5=CuQC9h{NBQ-FK&h3kaQwvBF6g&VePU%DHmaflDa??#tq%nIxhAk-0cY^au*w07T'
    'I`f(A+a?^Rl$v`zbIqVr&Dap(id(*#ps#jj4Jxe_s_UfXl>Z`9SEJ}g;@SJpUh}zr-dA(|V~1_s<|P2g&WqQg$13f07Lpb~K!kN('
    'K-nGMcM(UI(75wIeKsebpxdGk>#>N|a$_V2L<EZ@5#bTS<Rso)B-UYvwol*QKMkSYNa;)uq|z~Jr1x;IvS(~HJX?I7-F$i=7z;G_'
    'momGHQ%?p5M?CtqWcI1>J4O=ZXQ#%n%1jKtio_#PNP+VUaQL10Ynf6y89<R-J$I?7F(}f4X|r-V2_3EF^?H8LI2%@>BkCtpTwOy#'
    'Sf|fj;ka?@bk5U_M$D44e61LS<lT!Td)p^HOF7|?zC^{$bM(h5nmfrbv|Qk=Q%D8#04<GN#9-oUK6Q9HUmGk~KO$P{YWk@+>AmLu'
    '0zzP6Z7HT!d2Dd`9J9}k4aUyLDTl%&qqnxvh@mJYebN~S1Ty{DTGlpbfWyS0zJ{qW7t;l7`)m8JW*XG-TNOCd=3CGNNV#aUp>E-R'
    'a?sE*&f$q`CD{Izx{tkLKfK7R8^+1^m|-V-QAToB_zW^p#WviPql{pLskhF9!Q+CXc{s6Om2K*k_%xLE=3anxPC}8&1ccUngUmbz'
    'n`eOByUFiyUN&G7X|NgUQOg)`J*uTdR52B-DXmBGR+{S^dSI&d6v+B?1}u|&e*5J<nJr&{PDZW=VvL3eTZWho0q$*Qwy`4_vw0?C'
    'Wy3hG)XvSd6_M8B`H?afSQ*0p|1x<A#CE!z2E$g4=GS$gnP*sbD9gBTrbUXYlJH3hTb?O5e0Zq(Kk7NUSvptSE#5VGo%S+TEQ{;3'
    'oZPXdl8l!PIKwR}sX5A<9StUKlWfAUk%kb}ltZL#KlOv1e#H*HVU<lg4`ZndL#{5+DEVIjWX;4sbL#@R?*#D2XM0G9w@2>RRM1Q~'
    ';IfhKDS%p2tWhMO#CrWC=4x1C4+dBq^qkg=Rlx77LkBlZEuk&C>}Zbc=y{$|SjsktYdvAL3&Y1{25z4Q$(n=W^0^6#eJD|yK)L{s'
    'bu&A6_nAh-<QKCYxySSdih$-A8r93POk4}b)`>sxSff`4OMUd4!b3uRDANv&+LyCH@XQ<U>>0AaWhOAiiusVWPe;Z{MP_5tT5h#4'
    'h6ULhhrtP}4ZLk>yAp!dkNU#SIiC-VYE390Xwztb-uG0ll!IvsHNhtO412ZgwxUN<S7>d&$c~4u1K{#>PRe{5Osc(86d7R3{0t!V'
    '@LL(nEg2G(fOa%~Hn4oP^TrBhSx`vR%Xk8b;Q%q{u2=Ep?y4KlG8hA*@|k1f9C$%cI7FzsL(bYv#_(=O7Qb4hXf%!61$^)ZF$>mG'
    '?57M}W79{kO<pe`<fb2pun?x}KyGA%d_Rx3QHS8hd7I2bfnV|SEy^Q9X?JTmg=3Uj`4u_DG~0^)8lmxHZ9KIDntL~mYT(d!kC>?0'
    '!BW@@vD1VhHXG#bB&n{vf|%JvOXbt)Yl1Hxb0Xx{a5T~liHEslp?^!Y^aEYNfiBsLF(#bq8dRZ498_E`J!$})Mc`Q<s5FH@p6G1L'
    '9(;0L%wA(Ck#rrtjJ5bj-;%>Z(BBN`obcIMi!E?^5Bz}Bn5MNhPw7mpNWwrb&Ds&y<fx}r$mF7R!%C_1{c~2PJ0DRyM1(Wj;ZPvl'
    'zJpLX(P=6X<LuE5LERPRaPiaD4^Wtu9CT_qcFZx7Q8wGQPkmDMS-e?%M@oOJRtK4@#Z9UKE&~+MYkt(Oo^IlhlEmpCGW2z$Fs&~&'
    'SHS~4?M4myhfcdd7+zH?)hMA{zJa)#i|bx3HI56p=8V_9p_z;jW%@9Dw`sAXt%c`)B_GHT)9sXc42VrTNhfPuQyMatVZSi<0jIqZ'
    'TRWorEPsGwZVxkFS*P9WIWNWd4{3sWxh}{pg4f=GH7aG=B|uHu&!U5kz2?XQzSj!}ipkvXFl{|=N?oZR+LdMfSLWtJ2w85$%%?kN'
    'eEF?q1kiQ@kzVgeJdK%u6@#;sY$?xq#?W@oER&+|o4Y>6$AF)q1?HnpQm^OVJ&APdFr&<m54n?>G=8JXh(VDJmw1M|EDfw|C$8bg'
    'B>(Ucx>|`S_i}Zg!BOlncAXjM@`Z*k9%a<qMk%kV2s^GfU7HIiD7gP<Z2RC|c?USFfToi|WME+)nSR%|6ass@e<7Ux7j?GLe%MH}'
    '-hfjn+xzAC6dTZ8^>_RD=8|ssl0gC|=OB`dC{I6J9X<fKAHC%SR)wBIifU_mJEPq9ux8_Me_WA=;&Z-Me6SepA;dWj;A8+`vKN1%'
    '#!D3^geih~D9Z^+MIj})kGxr?&t~X-{o605#P?JwAGJ3vB}8K&_GdZD*g~ZvBiDo^S|*?qq??_4GNIVo5Wnftb*V=!E9V~nIamj`'
    'IYG&jJnm>em`)wI=Npye(nO<lxcd;kN?eJV7H&~S7oY*JnZwFN0B~F4USU;RbeZFTz{%b$O5_>9KxsnSTK!ujQKRJ1Jfkdd=S$}('
    '1S$o9E@NnT$Z0TrF*xd6=sQJG1EU%vVJD6euiyaMGO^4#IR5fHIi_!(EpMmU0FIX<2eqPr!CWyaYWQbP9|1YP)AqHEhJlk|<oj)v'
    'ZwZuaARFCdB^n?dkw+q19H@Z`p`~W8L&XexXN4KgWk<+f;&`Unna18X?4uuQ^?#Pt1Evb2oWgsTuhJGlBrVDaD{#xq`j^~71kXcp'
    'LX-)S&1Se=NCIP>-3u4MpV$AMD2U!AUIXGXFTOJ^{JwvzLI@K|Tj)>ndFg(jcSV|FMC8CV@Rkt<Is-=vlXxCk0-jO>*t5M9YsOxU'
    'T%ag0?#o}VpZ4^J`2#g63nx~O?DPXsQKb;e$8>0@`vh>1WE`<IiV#n=4(sI{XDk$(1F0#xrh~LiV4X-vE-B^XkR?v-QN5dc&mu`9'
    'g@V@KIjTuB1$bjA9<g(&+!ekqzeCJsQ5Xpo%5I_(>2b97xH)3rh$+j+z8Fb~%~0VB3M&Z#_rsx5SR?+Eo+)%?Ch(Wt11(p+nfr#0'
    'bsF0NnC|kZ{)|wDc7#`gx$8|?fmq7S2Hb7|&K~Ny&#i4zcFIJLe7)7*lO16vf6X|*3rxEugbL*pPL%}$?Y{B_doPRp0>b`nmuSIV'
    '<;i|PLECDs#VZASj3lB5o@ois>W31qTei$~4=nrhD*(J=`}(tmlEi=iN-7?{0&0lnJbVp!onG@~#4DFRbjZDQjOms5$kbSdvSQlp'
    'n;`BibWJcC?X2Ys5Uaq<2&U^t2D*_`$$*`W)fyzHx<IU_qXmy9CI5N_8d;wn=4<M#cWh6)zz$R}`U=U_W%*!f{4L$I$sdI-S&=gq'
    '%pxbvnyIBST<Rc}9%37b^5=RV*5RL;${?lp)?&m-u&vi$_*&!Bn0XDxN&k4z#~!2jB)t*5C?dsPQcqld!ER%8q*H7%TJlad*jCxw'
    'y7`_mhAfB7PBT84wCyBbyMumS0%>JnZCorMe!9<WekO=;&(0mFd~)yw-#<@FkiuBxB7f9RXCb*7-{tVA?dNez$IpPnieQdMH=z3L'
    'pb5rY3H=03T?=iO`7f&#qsqS1mwVK7gL{n?mD4Vif#gtk9r-qAa>M*yodD#eV@x1`l-|~H_h;9xf*MNSGEwVEq%IM#N7Nn$7$Aeq'
    'Dh5}=U<p)152C!mgp|q>8#a7(6@*<nFUS6VF}HPR#rY+N>s2Xn-9S74b6*OC`Kp5Cz1DR2nGjP0rC|oaG)`ujci(_-#Mul|rADbz'
    'L`p(~xR$);OK+HlIU`ly6}-!zPxl=U^ML^fhp+KWP?15=(GeaNN4@kZ`2FK!5!Qu)W}fih6S;l?hI98GBhY5dw&~KMLcnA-+I|M7'
    'zq|}i(Z$!KthY23pkZcr2bPRo*?Trul!f(rYeD#1fiS?prqqsnEG7Uda*PBb+ZD<*yB0J{Fs3aN`pg&ICUq5)SngU*E)uw%OZLQ-'
    'pGSkn2a=l4YCL?=m*O4IsgEm~6yq1{Ee-yrfh(|}t~~yeHI`}P+-FizaLc7w99lJK)lU<-D15_CzCjhFUKXNk<0*kMXHMMs&F@4x'
    '##{-dLeco!+CF~i!yQ2~oc7=30k$woS^?{{y+BPK<+RW|<$OIFx_j64O(qT=tf$=7+sjX;ibJ@y)d3hkkVr(p_F*Fxj;C6xG4l_U'
    '4+UalZ)i3&nka95UG{8Ru<Pl-z9?15vtX}aXqDfx;CIHC$1Ds_6|&z8h)x?#jjt0GK|!~id{SHFH=~c`%y--f>CuXTrwM&J3F>lg'
    'Qk_JoIEpkfc}r|BO79NvW<<V|mUh@1%J#v(+R^308iXTG?{W2AWqFbfbEs&=h6GMaYapcrG<lyXl{&5<To_Z`pic4A5T#BshG&m>'
    'BF-X3*p$^U7N)_*8LfEQ`VnY<S}95Fz#$+-K;O7!mNqFk#k+rao(fH`l968cEh!`7Lz0CKj^CI<&T7`O6LSyn7lTb&+h*)6=*Opz'
    'gmnA1OBL{lnWp(&ObFp^I2`KZEKdDpNRMhRRZx0#Sy1v^Q`oa3aHOb-jO_{|jW{2F`Cr-udrO^T{Bz&jfCd%WP-t6nW+hvG_nc78'
    '8Wk0JS)&YWe*3!vM6zeQc_pZ)xUElC(v$9_Xc+ePAtV$o_1!MpVmHAj*>9YG#!|kkpJ^Lkn1|m&yXzb@c6nFjcKE~{xZAy$p#jh<'
    't^G>dQZxkTCLb<&Tc`|vi4eAARoU&X)*`1DZNLg#)VTpwbC&Z|ty+#A_79tqx<?aPX)M6-UDb)pYWoJdUk52bW%l?!ceCz~x3s#?'
    'r7SkKYPSM!->;W3p7;ApoCgquD4B)qyM9%Qyt;0*->?^5lJ;gCPLZIE;ptw-L8B7vGoRyo&s>Zqcxk=Q`Rku1-trIgA08jLZfeXx'
    '#5pRJR7hITBjENl?nogN=_e{0OO1&WijS@$t<Gv;ACfs?WF4VtvzHN~9M}p%`5fiRv9-fQyu#|*oSDa3sX6eYWnaP+(0yx#=zDzB'
    '6@{M0O5pp>DO#~FZt@L8Bi#MXX{;b{D@P$4b-z*X%(51Nh!R8Y%O2K0E5g0*Ms@kyml*zpn;?;5xDc+ax%3I0SR{)i8@xV|00`S+'
    'DB`G!$jso?jv7mJ6{NOy9C$VkP5;9UsSa$5KjVSn-94r!DI`1FR7szaikd=BZ7c#@P1E&RS&qdaf@bjvU4Pz8)06B~m#C+py2Hzp'
    'Ig`W$D#*FVT(A0pYW1jc$o;Lf|KRa@TY?sKTWSI?604=~CY>KOwCJ`1=5R72?W^K0ZhlBL6zyC$914}O8Wl{;_NS|C33*!aZ`6fu'
    '=29mBNsF_w`9j#CxfN?^x!CTrZdCz+;q<FotFm35JC3PsK5i=+GDINq485A4)_^u@lV^O<SMkO&_slsFE0(}XQp3hx^s2~e!JPRk'
    'NjM|{lTd(wc`*&<1p=g2bI(brN278kmtvXeM`xvuUOT(T8OJ1*Qa1V5@I#{Zx-PQhK(EX8b(T{B19Eg$TL-fxmx)H={7!#P^ANw2'
    'HVZjbWK6t~Q#Nf&(dCBshkZLolA<(bSf>wqfv5yHIj54UBrpt)E7hmum=oExmA#9q;QRdzyJf?ES{4=>sL8I-H+br-f8#4(QUG@-'
    'Qs$22u2*pCp^*T-VD2lAmaSLJV&~R9ZeMXWV`jLoyRk)K+x#sc!6Zfv`r7=fW88uO6h2lm<krRRfCcTd)>k;G|J!I{GH>3}Q!L*V'
    ';^ADd1?VC8Fmtp%jN#J+|K4uM>+FRfpfYL}b83#2+^8zZ?~cg`*a6D>9+<BD7PBDQcqDCYU=(U1_mx$@NicHyCs{#RRec9!qMu}@'
    '7KmcZlc4)eLk^#{GS!Q@QK@ve?pC6O{Fb-osBYD~uZINsXy_aE5yk=lUpih(k<3?QMemn6G4Gwuv}T(GuCg;W|CHKAO$fBzITCKI'
    '55jwVbEL27Y@LqqXz=?GrskH_D;XB^cCiP>3w?&N0Exhzu+Or<K`AkDP_uq83#`_@Gu)L9#;h?}_ES$}DscUAw!2?4T!h*ItPPcN'
    'x^hV%8Kf(rr@0H@7nXV|IrIIRLEc}=w9a*jq=G9zb~9z6MCV|bQ*7+Cb}?(94!H}?IZ)DWb+ZF?62h3T$QtKNGhaCrhVyem9yvg7'
    'aX$Qo<{D(xpcknf6&d@FpsboeWB=R5Y$fS^z>le`_^gE)^Iw4qB@=K-GXRnmU(~=-EH&86b-p@Z#Yolkus=xh_|!v~3&)v^yHR@v'
    '83H^Jp>wgul9Y9bvKs^3$b_r7k~Jbcps;K#RBM2UTqDFU)wG=-t+_?pPnKY&ITl&0M*3af`pudy2zfeq0i>U)^Xx0l2dLuz;cX)o'
    'fj;?5CTr*rD!Y_h66UVP9N3jo_DXIZT<y`PQ)y&N!S~dllDR}!>&gE<nA?3OjS_hAU>wkkLT<*rw8?5!<IvhE!7W+#RRv^W2&ryZ'
    '{^tPC-Cj^zm;?HZqwOTJ4ZMFeGcPzHxf6(G?Z(-j5rG;>=yA4FeK8KM#y4&6IZ%L-$wpBWX}ec^UPy2HZh7JdQCkn4cIO#y9Hemn'
    'Z4NXmB<)+=^xYL9XOtcr5d1iUB0;{!nZ+utXouWOQ{L$Ob&R2IoY8naM1eH^7T<ZAk!r<(!!I6-9@|lIlv9^^Ig{nI`ZAG+g-#Ak'
    'k_?2;sAn7*7NoWgGHdJ(oDrIx)w4gh5L4qBWhIU%q2GA!Q1UrVH+m`@a|;F*5Q)Lh3MmSNH5=Ft+co8Q*=yi*VxL}yd-P;`Kk5Z#'
    'sK%%3!iZnYpxXU})TaXSYh?Dpe$`7A)CBj+AQCAwjw4!EHL=W{#<_zYP~q<x5q-;h34^U4p?pfqFQ){B?jzGLB6(i^OXFMpi|Qw^'
    'JgOU+3ncEx{*l*Oy16L$8~Y}WAPPsLUVPFeg;vg(g<X}{N4v<!%Oo)e;_Pcbm(@uLeqf%S!UEI_Wm4@WqgJ33U_@I}Rf^yk2AG0!'
    'F>S&++>9!zSGPA6%t@5Ody=kjSO=C&L%W#R*RTVOrnsqN#K**vJhI((h>iK}j7t0t@N^8eSmMCnTlz~7q;U};*#K8hS=w9(88N{F'
    ')|zl-dR89Kw{GV-qN$E%1;r5*E|^=0V4%mRk+)aeKl|v$T=a10o@N7k2>n2B3aw|$mwC>l5x|a&9bXyuz;2VCPZ#Cqxyni&em@kS'
    'N~6_yq`n3w?;K|?j0Rld?8m{@NG3(997@d${GGC-;5x?B8h;X7WQg3vShIt~eOM?bZ5gCbK(d6Z$C)kgPo7L`OrNKR&oJxIQ=bpg'
    'k;swk#h>2Lqx@-pPOtB;txEdP10Q|hHp>9Aje;|x2JVUsQ2uTiV=EtEd_%r6h=?0N7t$i1?nfL57<la>C#_ubg~QnPy{B_slXfFJ'
    '<hvadRbmp;j$0jT`!50q(yNxRk)+FClK6tBER_Z83+A;?4sBd&06BOT>@ps&YuK%td6VYAw&UJ3l=Rd9s$W4c3r><@S&BK#_Fb8i'
    '7c{)yaWR$LI6-aq19v&c3)QU7t>Wp0xdPremBTFpg*QF$6&iWDRCs|$fv_6A?Ga~ATaMyt3X%`I@<&A_1WCqpZh&(T3|})Bn`{qQ'
    '30E|82_`&)x@}Vi_j+zc0BEm=*|<4EIi*dboHW+resGCM^RPt4p`rciQ5afc(NiUXp5TOao!$Rkr;e!Z;TF3S6LzV|kxrHX%%qT}'
    '${wWg%Vpn!neEF{wZIMT@39TlQU5ho-0N}Q#av(;qUl+j9B%B*?@$kP5TO4A4+>gz%}VlX(K2x#hDh%03cC>OsUl<fUl;yoU;~tk'
    'nn4@0s8EB5yD-Wv8x8PbmjuUt(|(_I1W&CM9-5<@bz4urQNmXjkr5ix6a2SWu6gBR3%7RWNQWCChA!(d33wa2wj67n2Bx{qiynz2'
    '`Hp)Tk@%BstBvypE2+gQ8-vUgg$yL*#$EgA?OR(2?(awfWOjvgg_PtOo$r604e}(j+dg}cU~$PpAFvECMvntXw85Z&6h|W-K+!nf'
    'xI?wQfxzpC|4p8bVKXKRvmHg>tl9eb;+KCsT8arHf0y6v$Dr$YP%L+c@c-uNEAL-!IVlzRI(E+FeONQ9f+?cLk^=*VTGhnCVaS1L'
    '#I-Nr=vw>H<?Fd$-2*4|gDViL&jR?Ya=0s8k=Cm?A)s(^c(EXwN-3M&V%8%hE++52-)R_L$&HRBnd+oYuqx8LkccBu#(w&oKrsyB'
    'YO&o#5_jX~t5oG?3HCT=@we)bQiGO&p5E!{1uqcsaPhzjCDtG=98P4Z(2-F6{j3;-{}@c8E&WQ>BLq!U%6WzC9|lJ9w0wCXihxBW'
    'L?jn#N!XMK(=83A!+s^H2yKI*EFw`_E6;nY;v_RQ&ekpaN)+2cHqhSSyf}cM^?9yFMIl3iVhoS-09#&0>R@yitZcqlwd`2wCMXkR'
    'sz1b-+k3LKA$ls+bH8yq0+Si+95yy-9?<#1A>$rJ3GBD!uduS8TR0)$bYO=((H^NQ;&T4W!iyU$S1S`XNrZv-1Onx^7v>mpiU~OM'
    '3*6?XXIL{UDhzLhhfDILd!%;4U~PK_QmdlB-u_hv{i*tjiD|Y#;Cvd|cdJH^9_-(@T$V-3a2apQ92CAgU1V^v36_&^*6_i+&BSG@'
    'lBwAeo&_Z(r=nPzc0++r^MlY;OFFRxQ?sNoz>e3k?KAX3I_Z(K8KM$N5O=ObD;1*NV@aP8+3FbLuVJG0zTv3MKzJfUE1G0;9_-mY'
    '*}9-bC5CB(s-qq^IX-evYz#}aBm~om{K!Z_%9TCt*sMuw3C%i_vJn>cg#BdW={A8Tn|Fw-d!f%awJk03`&2GP89_lxN-Efx*^kc>'
    'cIsQIIN?r;yC-YD-w{>rD}Xhu7@}HFI`H-_iGX`%^dKa2zd&e5QgTVqYR+bR1_@x`2CBuz7QZ*KHmZY&?!=QH>VZk%r&6oytL%;S'
    '^JN65rGTOWaMG{>0@ZWtMw3kX+N_gJ*S`zPBmr?@EE5G!1^v)tDn&kzrf|ID$ZIGpV*cE3wCPZdz$yeD-AqwVI7zBhBXTMO&kWsM'
    'r5Hd~;#FD%1Tgq$*MGo2KQLMkg2Dn2a5DRZ>KMcw;G*o_;7U?Y$DQ3kf_dC+xh5tAJS0L;hD|Hz=gx0~#pbV3t5_U_n(DVr{;%CF'
    'AI<f%xJ;2s<N)R9_j0s+&+-jW0Musj!(2RRT^Zqmhs<w};6qJbes8xjfyLEi+m`)zqB!3VKC2DYgN6*c=UN+KJPBO25{PkMV@kj-'
    'CCF#zg9eG4o^*<nEiWU}(cJfYbZKGNPobuE0cs!@xa_Beo`K2h2bnO=rK2=;J;9ua(1uSTaTJ$h9uCKa12|cU8?sKo+sxD^&CMAt'
    'Q@=xV{lKs8jYZF!a<kl{D{@0K%ep?!<!Q4)s(q#)c}TpYs-B(Aq*;D3m`HMNagQUiH#;ziJ2Q#B-r*{`Q_dI!#xXwbZGcH20wpvR'
    '%C5Uhtmi(Gd3YwX))5Fhe{rH5Pw)xO*Cr7_amyJCewWwE@{>^0xMjQ_bZi#P6Y?iDo(s`fGBnFN$e=&sm9aNWT1)-HS)MhC<dF?5'
    'p4cL!yjRCa&q}XMb)V?5dJcpX%_XZp*#e;2hvkiUg2cBUBoh~JfdiY=ulcO}N=ijZh0W%@>ssXiFt(OaGZoRpC%WhGdhG;i4fbXt'
    '?b+ovIlm#}jfEx1eO2bYg$^G}>>0MogLk9gAc8o-m&2`#^4`)?L*n~-Gn6N?%xbJl6rGIrYNx<Qd`ZvEkcld>_Z+0^47M?NYnLjD'
    '8S1^jzf4PCT+q5jD~7vVjToy0&P?N3sbTLUt3-ZktkSY=kkXHtQCftYV4+3X?90GDIUybIf&n83Y_FbmCC|g>7oYVcNgzIDiu*CN'
    'h&@+uwDORQ!=FeX=DOTban|32rb_Cb(NW!$jc?OheS$EmD}JMuRom09Awl6CUL02~t;fhE_O~br!FMC+(R;wNXsOQ?!mThFK;$pm'
    'bdu?Ap~#V3ifZ87V*K+ViBb0W-*X0rD0YcvTmW=T;lDoh&ZUA>!rSC8PN!W97Q6jZn=MX!bN1m`ARccln11D|p@30>AP~<EfR}Dp'
    'gHWSRT@aL@JTesMhf>!H?e%2BKd9`hQd8875Qlm%>t%|2A)$u6eDY&PCeVP;7lE^P%ih=;gk(>~>Wr)UvTsFljO9qkzsH*fCP%l0'
    'Ki35TWlV{Tk^CH>;E<lRwbPzT%a$e8UkRn3aA%baqd4X)zX^Q}5CYdW;>oyzIh2YL5wJ&~1R~##hT+r6Aj&S@bvwh$2Vl##Hix2U'
    '6xI;_4Vo`6c3spq$HbJg>PD&h5r>4>`syCb0*o7)>=KDF3vIj5sag{tY#yqf8Q*s1AS`LpD}M|%5}paPmErEu@5!nqImoWf&hBC0'
    'h1Z@_v;)P=9_$lVt7aHtKy{x!o+X5o@wtX$?bJ{JyA)sry|NdV#&3pW9<=!i15Upk3c)d3=ep>^*Bolk-S8|<3}(tWn#-E1`q7J3'
    ';qsX!n1ydS1`H~#%xOEiN@=-`a<)aR2}MsrKLu2y*vAa}p~;2rBixUc1b~=dY&2PY?--b*V5|3<#C6s2P1>UFVK+=<Jmp1p>K3m!'
    '6Dzi5>c|fSDC<eB`xvmCPe-H$xYirrh%c&(T{jeFRP{B$p$Y91Ity+GMD-HR-djutudfDO++5j>>O1M3Hru*Fr(~|Bd1t6?(CK8s'
    'u|xUSim?N=^otD!LeXZ3H~!g}t2@%)Ul}&yvhX+CRA8Z*^t;no0o{}<UmJ`v$hVi$I?FKClYTS87S+JhhMAzsxx*G}oDa?G;EtNx'
    '2IV~n*w$bO9nD=UVD4KSg+zA4*2EWnDV9;C66TAQb5OH<YKc|@&yeKMHq3pXYSp4wiacz_1AN=#XmmHrl*53?TL~o!OTe1(oDg81'
    'tJcKX23PenGx&^KiG>Np2+V+g=9%`_Bg$8Vn?L%wZ(ZiASZ9O+h)yCME*B=PO8*G{uw|&05dy+TBu4!K6E<mW^>jYy7|0zC;RRL^'
    'YXXc_82Q-I<J)=qL6;m2|8qbV;}^f*^mP)Ujjd)DxvKkMrmqrSaq6;3Vu-ieZllTS|LbI7)hv@hGr0{cj10m)EooI-<k8AF%wOr$'
    'FFRB-Yp>%>3u3JKAy5~G&Q`@+-krD%lJ^@^)h*^)MKLRSoRu^&jX(cB*)1?oy~Hu?3yu{;eDx(i`j0Z2!QqU{tC;GNvOn*q^$R(%'
    'V_Y*DkUrSh-BLKqYOiYy4F4Gi3)~R_n@}s1nb#^uH((JVQaVM5`kK<zcGtZ_h9KGi{cpWv>cesu#Odb-Z=^in5Og?C)Ib5*><Shi'
    'iHImDhj_@_|30k9H*f|%0=`=}6;N()5*};Q9z;H&*8?<Se1Bfg@nqXDC0kl3rI<JkckXwY4!NIXkt69=JO~Pc5`+WPiSOlcuQ{Kt'
    '%qT5RoDTIQXMBivXVt(ld5mkyy)8kWiyD$0+Q{13%SsP+3DI=)Q$6890>dTWTet$m$uh}U2MjgAX?74mA)^1iJat4%Qb-X94n2Ik'
    '#C~Qd)nHDt2r-N?2o9J~45)zysDMG1@|mf(^h@C&V$_nJ9$s^CaaG;$Gwzao1s=eD<Q}Nl!L?$RzXCLxWg_PdNY7-?Z%~opeBGa5'
    'A-JD8yW3L7!;jzU?7|^gbfZQEhWjCBdfXiO04ImB5bdYnPmhOu@}UcqA5vE9dUiYXJHb>^+5qrz#VTkS@y@M)GYs1N8k2w%haMFq'
    'Np!h}8j{u+ZN6p3lfU21X0oweP9`<Co0`y)<qsGm5(6v2?10Sv5SkizNQ0bii<8-t8DSz0B+0&U8%F4=!ATQn@>ENcoChb|V-#H5'
    '#P8KoNv2xfD2X+FDh8qorJAt99p5+h!C%Q@k40r{NL1iM4-HGsO#)Mutelv*ZbK?Xx&6L&=;<VU@<L9%ju6JN!Zura^MjVcrf3BE'
    'gVhUVLhU&s!YNt1%AkEDE4^lQFG1W3+|tI}Bf=oMN$JiM#GXa%t~-hCTC_Ks9qJb-0(|rK#}*Vp$?vu|<6NJ_pA$Z6sY?SO!ph%1'
    '67pEcCc{5Sw**<+ilcA|)J6Zik<ch}9P)Mm#}~RlMXGu;G!@}=fR`IMHpZ?RG_-3hYfzMuc(i=b8xxl48o6`TUU7)OnzNV<wCoRg'
    'aPFoQ56uYvNDv7!)i-2eb;7~e&G##!0Q!MyJf9}_0VtY%V8IeC_n^KVqGT;L<N%}!fZk%VOirA{S=nYVtHUrP^LvPRgCmtjm;Zd?'
    'T(x(rlO%U*8Pm6WLfH}Hz8d^$kY?09Z^jM-_Yfkj_hx{8b6|oxVsUG-#}3ug5TZw4n6N`lz8)x7<;P=O351iH{Ao9`pKe^XqV_Sg'
    '-eL!EFz2-#DVUhhDl)7A`I&Bn9A}U5ne~o(6ntXdN3w58kvYpI4U;bX{6s?RTjAi79~NyK!Y+5zxnPub1Da^FcXQ=O>RwTVinR#H'
    'Pd_eGENLI+il}0fpR{PEk<7|*Rmn31IAL=p9TBoDq?YH?v6-?DPqXU6&3URqC>z+ybZ=a@j~w_6X9C||IF{$Y)b#|N^)oBrj%6cg'
    'xL0gjKjYMk&5xnTEod>_jT(pJIGvhJvWJh!wlwCJ*i<!I5qX&z&bIaF2v`mQK4U5OSJl01G|m=@tg<tPQus&W!EQ)rW$T?11uRg`'
    '$^lkGgH2jOc$CQKyKl~9n-^PafgAOUd1jq?0Du2e*7200oc4NrX->D8XOFD+x<jk0^Z4x}61csR=ZJL6cuH*vd;&(+1IWBPR1y$+'
    'd#5lpuSo_u{X0VFPsfVIFh6JN-2*nzma!LPNHQ|GHYpSS0ZGwTRoC`#{=u&1gU)?vupy@ELL>Z6byuZOoMx2;lT-C9V5+z%qv=>a'
    'TAf?8tzs~6^V6rI18D8jMlYFEuE4egm#H{CWyGW%)b<FwVeTMGbp<l&6}>Tv08r{E_B|;umlCg0r7Ko3ia`RscXGo?Xe~hwnotYj'
    '?`nAjG7Sby1NlaET5S(wVoh?N^TiIm%zqL;!Oh_AbFKfel6vg+m^HrD8+*_|%7A*FwkMnnP2G-H^7g0qHw@-AR2Ttt$k&jpG0ym+'
    'm07MYCf*l#QL?O}E=&}P;Kx~p&vETHi@@-&mc?DXC<V43))YbkxkW#pNK5zWCoa<J!b5!@_{(%U;)(RekTGSn*C5YL#Cu|h6sN}e'
    'i6Pa(c;gk>(gzlFb-X88)Yx&jN;N*HKm7%_IFWlfqcTYW!told4D%I<!cfuB{L=4iGciwzZ{DZlRPfT~d#)JJ_U!ZM442ue#gXk2'
    'EYeCWu}JERIL~O3wqx<R6@9&Nm@_sDBd)4gs_THB1%Nxwa)@lEg-1okUjx!GV~CBRSO3`JRey1%e*K0*qw0RQCinF+5Q4}_4muzX'
    'ntGwy4H(${C7}y#)tyB2HX37E?)>v7dIfP8A0yB65u~|-A4Q^<d_&76yQ#{yof*aK;7dK;Jf!U}R&Ixg>l}C+;SRHlyhHzYE13gG'
    'PS!`ZB6PaXd8I&Bq7n2d5|Jz2e$w$)0e}-d{o4`3jqNgcS1DC#IT&rUP6~;aWyu?b^*nvN2H^K!fXDjB%7he_p;Z%j9}5&|z+mgs'
    'YeZO_Y`Zf#bHbGp_H|)LaGoCl=-4JYA$>M=7=VJDnfqXgBSrNzIt@#Zip<VQDQ*bcc*PLd1ykCKlR{bWUB>+Gm1jC|()Xe!m^ev~'
    '+rvy0R?UXg*QlSt7$&`Xy)&x5Q=rEFohg^8J^cVs18b!FFQU2F;Agj06`RyW8HP3FuEvbC9HHVPw#Z-w3mgOf9Sx`#$(%~I(ppDv'
    'n>CqTBZ@mjTWjg($|z?G`e+Mna9<hu>kH?CWB;~*8Fl)9{Ck&rf_FiVD_TvnwL&#3wMLf1LT}3!6{Dq9DE;Z^D_B?#V%Y^|woys~'
    'bUprK(#^)qwtiB-G#oF_VJPH;Qf=|Sqe1ryk8Qg;0r7$fNY^^V_0dPBLFdBw71#5+-$-GnDkB`fjwbj`?>71@U#QJM7kf^a6ldOp'
    ';ilV31@Y^TY@K6EaV-X?saf~)+%onejf|}5@$KwtwW6Tcn{NWl`WF*r7y>;Ad>D3{qy*;GV4|mr6_t+RM=rm2^bQ(a<+`tXV2lEJ'
    'H6tl!+?ur)EQHz8<L&xZsV;0D9jIt&Ok?ay4r0=JTfxD9uX)Bxx|17~uz%68=~1tpi+W!frmn3!bz-bXF;9huad0jOeQ-LxptkpK'
    'MfI3>Qz{4<6T>TzU-}o&c()o#xHS<e$2Hb|In20g@R6K}LPHonYya8TyTtJ;t?EXP+okKCEU!%0HEU38R;0e`jh?}M2>;`7OO#9^'
    '*`78AX6L@c#=)*SEFSDw5znoov$)t=@N$Ffm-YfF87X8%BGJ-FF*dB4vgo*_>;Lh5O*ZVBd#xr|v0x9oKHtYlV)<(P;gbBo#CGHv'
    'OIwdx0S?2r%%wZKZ;nQ6!Pw~zG+KWoH_F?B(49uQ+By|k%F@+kM=xWO=qDzpxc$jkYhE5>j6~{?+1^N|yMy+=ifz^GWIR0-J<_qX'
    ';;A5H+@IfUz>m>mRs#$Ly00-azqyO?2V4d^mMIa2x?vT>fRR6ZvBDB13xblOOi8aiP;A|Oc9Y<?`auvia*fkoKH7T|k86a2-1to|'
    'N3RsKycM1lg^Z?Z&r5h`j7mB$(_5ARB?ikcZrQAtR$YhY2F#klbCI1iMD_|VJR`wLp^~YVEHa<Tr%DliFo{kf7#GAG-afq%GjtS|'
    '2hJF~_Z|O;g^fjZK$IGXFs9lrE`bNqkErp#2J*1-Q&EG7r9cHl5_KWIRJ66aYwMwH8J~{&r0-jK(LY*2C>g$1{xiY*^Dvn;J~U-H'
    'j9E}$eB-SofzOv%5$TL^Wir_<ZEKawXpnIgPI{*-^xL3Wq`0ASPfTn5w9(+6^93Zb`3S|}=t=<5AA03nTY4qy$&S$(=={@;zgr5x'
    '!Z1Q32I<YZbN>%wvTbLw^HUQa=-mF4n|iy$uw@J3fCjHrfqCxdDWrRueyt^%gQGpc1zW4^#b`lKTN?;X62Jh-BoiRF=TU@<_gbZ~'
    '-@Kl}OcAS~+lv9l*{Bcs4GM2>d(!cmUGjhqS7%XzaqXM!OuZ5xqCSffj`s9nLT_)FKji*Zcw{375aY8jFr!yM%T&`<;w3fTpO|(C'
    ')40`}OT~waC~V&PtoAji!bI7vaK*=VjXNmb1n%LXFuKJQbOCC^H?oOGMLei?IxQN9K0dxmjvPa#x8CX<|Lw<h6Y=EEKGVIQwWX%P'
    'Vo~-o+Vxmhj1H9*!5_L+nLFdQ^mb8zQ700Tvng;>mQ!t8!1P|{z9fMn<tYT*&}vymlGaybs>t>$P2Cw2;arTsFnF(U6iEbrN(aDl'
    'jRTE}4+}qU;KNFH@8J_F>5#OKd;p~|D}S&wXSi)X^#R8Jm%Ss-B+LXWAT%l4PwWLPiy0RIupA-OzJi0U`r!KOT@ta1`B$xXE557L'
    'nz@?u&T0=~e=N`NN`~Z9NbR(o;0Lr-+-<Eqv<{h@a_K<}Kh0Vj#Hk^3#{ua7H0=fpIo?l>oV9qDD~=s~RsX2zTfVxxv~@YyU;5(S'
    'k5(pq26P^FP5YzAOtTvf$XLs5g0x>>h!VxUmR{!S)vQ(-Dt4-fK64>mRF%-CkLC|S|CgCf9Tz^#wuAtHA@K1lJ^NhuY=-e$)Mv0H'
    'P-7aqB|Zp&xI&6RtY75c(y3C8dFq(psOBu9J6x7--m-o@AFL_CGS7*?G)k4=Eb-R<A`A86e7PyjXUu=43dhMy^FB(80OeN{MW<U|'
    '9f3&so6|{?HDQrWu_AH_frvS@->Dcp4^~V7u)haC4H$I;-REJMEMyP1Wr6b3*A(OK5dx#%Qu(y0rBDEN61^fo4d;aV>7W`wMLI)V'
    'da57>D+v(S1h{|9ZTFx|uPtt!7&n!N(iuQWZ1~_rUuc;$7{)S`LH}izDIJP-JsFR2d?{?8=1zfOL%wx`OJWI+?|<t}=%2i3;X&+$'
    '=lj2P${r!DROu*xiQB6evGQMh^>JhV5#Cu+1tDo%4L&2=&Zw0nA#1q?-+E@}j9_yRpwpJP=c*iMBbwybzK>kv*YX$cS{hGLyXDY='
    'o<vwRGJvUkI~gg+C4Qj~o1sCwBzfZSD@WoW7(7aecmG(~?|xG#eA6+iDBz6J99hN$tx)rIGAuKxbgRyy)pKPnCV<2E*DYqS9|WNk'
    'XWLn{VDk8FxodUk+8l3J;(+x(18O#7yhG3ExFxfIBJr>(?yNFAvnA}h(y7*NZGCBOy{|Cm-$yu@KR_3q*k6x?`h1+#V=Hbw{;$9D'
    'K3<<dL`>Roo>-7_lPgVrm89)~6beI^n1KJB&>3}&B4Mbrdx(D=1EKTY)8jI#+dYeOHykvpy(N*amxfqR0Sedpe$<rjaEm*pI2rrA'
    '+6N;4T-8`4Tb6+H0FXrLa9I-5i9m~N{G${?6$edJ_{7L(j+)v#>autv9^YWId7HLUsfeXmRZ6Sc^M{02wqSfXti6~Y*g&EvAT!;B'
    'FBY*s>1pl`YULATBi~X!y$yl~;L0!Hw;gGz7dtehR-krxNxEZn662@JZV(B3?+pW}+^9I&qoXpquX_^Lk@z=q452tq@1%~{sle~u'
    'BkKk1cc>u{-;McB{Pl2aDDbx5(OO0f38qqsB}!-$JF>kyv%Rf7xCw~W3}~~8xxF}3zZi7Y*LOIQcq?E$7b+QsFrEtuQ5|57cwIxB'
    '8vex2fAcBcEw|7-mR*f-W)g0hvM^pp!2WFb9%9Y1Tc$uR9yJ0MX?#IUE|ni~uD6dG%B{)4y57;D8@tTf{<^WDH*BBx%jd9k9IADR'
    'm-vVuCx6@tHR@Q??meHC|3l)+?|VMNVSYHWYhP!u{1Oa()Ab0Y2Y-#7+d|rbr0XojwU*&Pu+WYYoH;Fm)7jN}%brBggbONsW#k=}'
    '8^2w%@&6h*ZB?Dq#ftwpI(z$k94o_1p}-PJmEKum+Dih(6l2wD(;s#1f5|x$marc2Q@i-{1gqGw&;LQysHdSI?<pL@VI5i!(mHMX'
    '0j7|Z(;f$vy(=e1Q)`?IdX&~Ln&NIddW*6+!p#M62A+}B7`TAY0di}b7;x=YcL{;9bN*URiP|5kOPo_|{$C=-9*TZN>>8W~x{GW$'
    'tLXej;~7BqIUK6^-K3gmkIf;&{d|@CYEt!pT*fJp067~K&UDWk|5hz5pbvo=K00aIQBiaSSsyA5`mgaMO$WIB{Yrhuz3?xU70i3@'
    ';T6n}q-pe$b!ibUU7~npgqpDhrIgQzIa6u$k_hK(eO%P%5ycjxM7G(w$V!0a{DX#eJP<uLo5V7jgEsayMh<{@Juv&cU5rt@On7f!'
    'zvIaEL%rp=qubJN%-CbEc!es;Wx4siePjNfLTT#1cMhL=gVmhI0GS1&-{YMukzO;-T`doh`p#b&Jv<-Vmxe}2O_1IDMfrHJW?o6{'
    'zrrX}o^RwXJs<HD1tmvOoH`BgC*Di)6TcUTMMce^2ps0fVRlr3wsQYv*0Sn@zcD!O&ys*7Z*L-{3wmLi^9Dy0lXNW<zDO^cd&w?R'
    'O(c*taz(V$Q*UwK)pr6wq0G8)Y?BYVpyUZkO-Dkl_pDilfIcx^#KQoY6gIZ+V3-w7K;5ys#KK8QocW&{(qk;!N5e@|+XdT3%I-5i'
    'Fy_rxkd47yi)8V5rMzr-;JKZ5N^vLs&W)D|>^}3mXWO2gKj>i$eL+}DmBN}2fWc40nleq*)R3*#VmHpn70VZs6knUt)vB0=7)@!b'
    'UVmU#&k!T;U>t-@>`1CPM*S*frkTkuCtIP(NDMh*d<Of?<DKm4<&Z!&5l{Yy3&AemA=2N${&Yuvl>L$q=VfL1FT$I`l6dwa82O5l'
    '<{st1rFvm`K}W_r`I~o^jHVWbAW5DT_gb{xVF6FImpls5M;0|~@@MX+6eo{UN1n{?5Em<b8<{|>P<_g|vZeGRx4K(3d)kLnPi_R;'
    'g7-m(+Aj=${4Lw0*l%<(l;G%O@}D?TECce|N<VFbyzHMgL}u|lu<EAXFG`{-9*q3U)SOWOL5u3OV%Mz?36bCB>f0T$!fs%A1`cBt'
    'zXzTW>P&F^|L3NMY5ouVwke#R4#()JPCV0f_rmwK=vsIdcrSpM9WGO_y2__<mf&Nfw(fuU;;ydP(2q{hARN@CC<)wUim~Dmg|SEV'
    '7)N1<a7ydMLL|d<wjwe#;}m`&-rWf0#(KuFAKi1zhW!yjEicyCVAti<x`!^X%T{~jUJyC;`yVLDO~4)^eLN^DcLO@MZ*+M2=cx%F'
    'Le`79a&}5>;;R{~3Wf4bS4w}W#}lhHcsOl*{Pg}voyShCK6Fr9+I^rjo(D43KK$U%6h9V}y~m5$Ovxsmusyk!r<Kl>76RW6W88mo'
    'pZn}w&*Aj@i~5hdFq`mDYK-j(+iPQT3ZafemQ=j$TAh52u>8&Q31;YyK$NaswJs)gskqu_US*wMz3-@0QZ$3jL)bG{Gn-Q-6(x8`'
    '!^DJTS%nC8DY@xk-i(-@R3+^YfXlCMFOtFj&HROHn0GkUjsD3#2=o~Zd!fMPr-Igg7F9rgZ-q!$rw$<{sLPJ;8#^@W0?c=$&6Zt%'
    '9FhiK3hB8ZC@ZH>Ia5KRO-0=Ej^Ts1rrUxJI3W7v`~t8;X~5WxX7+Xr5J(*$%-vw8e;0#-VppZ`%wdZ~#FqiamDh&nA|;OWgiJCD'
    'qf~|ZWkv2WF;us~#~kFHlP(vC?^m;5v2?2Ob({XmJef<|>SbqQpGdJZ1{0e&&Z0BmHiv$%A4#-IFT4=h1C^6l;wj+KFwY3miN`z`'
    'd5EgcU+)vg9kl&T8q=H(Q&0b~`&e<Sb$lPi$N4;NZ+Y~4rM`i9cUG-RrV-eNXW=2agGmAKGn$|k58WAN*l*D>0|1s3+eZ&GzBDN7'
    'P%-X(<Vj!%ARMm@HzX23g8FVZumY=yV<{!cm~tlS5evL({xgD^+!ks&7{sbEs-u=Po(ZArT|tpP2c_z&NYX5^`LFmFNs)oINA{qF'
    '9_&{QF5g+X*vMtaiu+eW(I=o&K|N*9v1uqa;|ScbZcFR*%2r_{vT@rsL=}9!{`1H#yv)s3CPcx9J3E7<wwn>ymKof&(M67NDPtxn'
    'pN<3TMubh1Z_WU=b}DU^?tqv9u*aN)3>05Q77#&}B;yGp|2%QMLgUs+fmi|%f)c3gf_Oj^<?yr1X2_tjwyZU8=WzKwvY)2`^}?e6'
    '&+`rsD4L#@zP+?|b|5Pcv`9H|4GX&Q)V~X7BkW`!22=o74*-I@4+b#I-7i_Q(^rhaBX{9-eP=^L(yKNpw6#~Z^MDD!!q0F^SDMbJ'
    'B8)o4aRKct<VM{7M~Eo+q!zf@n1s)Z*L=-Sh(~BRQI7$b$ezs3j@4+6R*N6~G4wY1uzMG)D)F%F$+(}*&+cU=tXH}ST}KCPOB87p'
    '7CiisReM*Hvd&#{O`gD9>BN=yXZC8<%b6vMh&T(a6E63L{{l&mc%N?{5)HBin|O#Gz*=lRqp-L~X-d_N$9?C=DG}G4J+HhSr?egL'
    '-^a4i4G_El^|YWg8BgNYfW3V*<=sRdiNsYM^|9SAfqKMQafF^4#&r8xp#BfuRp&3fcT0LIYXBEXx_Rj<9t?bYydK+xE>%U*Uo7sD'
    'g9SqAJV6b5udh?`S!e(u-EL9yYLxLTM`tXcurIWkE*+^~B=(k@*dpi8i!%4j9`pZZVR1hYL;ED);K`bE8>|KD+!N`$s`lWrUV7Ww'
    'N{SFrY+nOQvEx4;V64+WO#=aw`bEx|fW8Hzu&=$dY8LR_ks_-Bx4E5oxdn_mLRe0GIY;0_0?P>6p;t=gFV~D;?<-XV_zUHa^c$95'
    'o`l@jN<p&#bb?mn<N4|CKkh^G*72U%(9C{9RRc-+AZ6w@=?*zYTAsY~s$Iq<veb|6!{TsAR(~jSajRQNQ#G|TovyzR|FnUu&W{{3'
    't~<u3r91IxHm|7&wJ&iaq09_`Rk4r@ksVV#U>1Ab)>mc8F38KZY$%NZ<Gk;uoJpkG)HS5u7mUMFj`+qXz~zTy0eCy&=(9HoU8-n;'
    'h!~_@fU@H0`8Kn>{0-!Iq_POxPmK%dXRJFKdK7UQA=R1Ry&=w(cj}t4&G2o$>DF>AmZDJxr>&X4XuF$N`gh3q{WJJARMJUP^HXLe'
    'mw<o6^+RAV{BfHwtoQ)m(j~VIGE@G8cjCM}n!bvxR=18=Mi&#BA|k3M&AjqK5j<)F;&2&0#&8EkzW{}543dOl6>{r79nZgsG&{Sd'
    'EUZYZ%^^rmiv`%Rv6EURZe`cKeIRXIOm6FC>?l*bYX<-0%1Z8pXyNv)dMRuge%&rAB^`dcy~R3wu;p$aU9ieAx&G^&JJS8r?iq+7'
    'IA-CFy=mJ;D<Wg4W=H$01#17!0)Q{Z<hrq2b*3uMYpom`y|QnEV5~_34Csv^GVM78hI>>V{zv}2Ag)9!6vqh9R#r%0+vBaWmln+x'
    '!K5)inFpv+NyfJm<Il(ab$F>7%s)5K&3A6*^JARB`xdnnnd#6Nq7W#zyE8q_Qp`Kirq$o5Qmf!r-|)9BpDAYn(p}1-4ja(VZl4Ts'
    'etUe)B8={Uma-59j{9Ue|7?a7iA3`@7G<(C4S>Eq+W&n13AOy@n0NTL;qa}7=4~u=n79xly@GOWYDUL1Y_kCS6(6teYLs*>u;kBz'
    'B*tO;!?*wo1LV#WjBW{IxY5v>cAVM8u<3AwWiHvkBSbzFl%&Rt$enn583k%aNQ`!44+aRHM+~BQBw{En8mCphle+e;Lg`hpV9@!m'
    'v$Ab!(Hkv*58w_gAn??!uCmxfNm|JY_<x@dpaZ35s51`A>I3)s?*ADoN7i+-q%X=NQ%Gzb$ov%B{6Zwb%6#IQHxz&Db>8Uxxt_nf'
    'wg<N;Y|bb4W5g*=eyP%*VULNc!I`xnvi`Rlvp|8Zgc$BrTMyAm<Olfkk$I4h+DWxZUKEA<xvYh&l1uk1!{)OCmf<iJRQFYQo&}0v'
    'n&-1y`>V-D1UT1RBv6rros6fBw`|+ts~6~hsq>Z1UIV9PAND?MLFbB<sl{PDcz?jF^chJakeZ0xuDH+I%SECXbmO}qIK>;NMP*!3'
    'oDQHNEe>M4$VLqtyc?1wQuyT?50PIEdo0AG&MICDA@KEvLu|{B(wH60YHHwGk*Lz=+8~xJxcm?+|CGwoH~t{~U3$o`48ij`yx}Y*'
    'dQ{h{kJ}mHC|G+yi(uEM7D7CbNAH%IGkISMq$%4-l+nd8D%jfZ5eDwE{j6y6IwB=`$W(YCIl1PEB3N6K`c<yeEOs`6skS47X@b=R'
    'aElHW;W!_Gpqe9>ZkGp<_z^o7EVcGJ{k1W+0WY=RJtvp0nvZ+N7YiHF5yJOJzt_h@pN^~QiGE$ujz@FosONW|u@J#N$+pS6c8y~l'
    '!h-e#bN<{bi;r$7u~ZhBFP}>92Mqgj!V!apXv(S`V@s^*gU1Pp)#rPa4l4y5!ph}!Ghd4Sq>74?)6n)+%!=ORIprp+dCxUr=q-j6'
    '%YK?D;im(0+rHMZfsidq6sD!=a(lY%W^$kf1W2Orx9W>l`Y;%QZCu;U!Lmwy#V?LhyrH_}(&2X~ChexOPeuegB5gQH2k5B}aEen%'
    'qAK|#qo}&8K<OKgU-@eIaEz&IYWAhX6s;e8kTS8x$`^@pbJ{EsS7X`I&1tBY`5i*Di$$rv0e5p#d5|ehr;+yJuIDMSXeibmeNZJM'
    'I3ax@%AQ}Dyp<Dwt=&Cjx(I01eP?@wZ53@p$fRlNIS3uEPe`Nww)yaQj6XfOocymF^o9Z9>Y=&S(K!_I+ctUnjJck#W*`)1`{+Ho'
    'X^=j#(Z8DR(&;(DtzqlTy?YQ1au<hy5h3un=%ysCgkz8(%pkIgd7*E)NN0^$aNz2Pz|)x5CL&bHc@j(oBu0X?VvzvNox{=FZ0I*4'
    'z&XDDwzdsx&jhq1B+NNVNZZ)Az<9vUqfy7dq~H43ND}3Z$J~Uzz~`V<oT=o`%zeZ)5Ir&$if(mdIOzPE0iY4%M_dT#s2?>qyXA-E'
    'V=HN2j}cec!#PwK9&lxPr;(h@`utDB(<@#An|O*AoLZSSQhXSxkiH^3@TI_PnAD2GT6=7~#+_J*JT=W|DzD5k%gE4T$4t(|=!5?z'
    'nWz8!LbV!avo(+VrUc>U&<j9<aS|sOc#0u$qmc>aMQ!Vc{(S`HCT4*hdJ?<Y>;bOX37?_^CX|dZn;OR%yzXQ-32!QpbAKh};wOhY'
    'SAzQFjUjVq9F?(R)2_wD<orE`jkb|JTVa;24F3bed=%sM$h7P)=W_bvm>jAfALI&8Ab=Hq6ZAs$l#bFG;Ku`?2~udv>jZj@`i58>'
    'E)GS9^!v#JcbE|~`XM-hKpB0uZ#@=|&?3!oG#=t!rGN0V;(;W)uwpTT6MB@=sgpJtQ~c_D?IdOm4fTti+PkrZw?fm8MMp=X`(*tt'
    'jtVZ6*u*G@q8EQfqNmB1mXTgU5->*$j|xsLNjzpZQ9$pg3uN-)CIL>KxO0(fBpe)T7Q^9OgTJYuD={W>XYN*ZWlt*TnpfBu3WOr3'
    'gxYhA(c_g38+qgIuf<|`%Tng<>bqHBrjx4P!Vh_%ABp1=8d5SDB=}Y{$F1gcNdtBaxE}n1Okjr>`_;Ewc9@WKl_%Ex=RM<Uu1@T5'
    'Bd^iOklL7HrwCy`?VS_nXP?>PUR|1V10s;0yoKvMoG6;uR1$f=e`pOgGr;58EOeCZ&-(0n*Yz1e*|!Vm^>|>NC7Bt2c&e!-imYv#'
    '2&qk$Nlpqr#IY@$U}?3e81SfWLjfVt<}l`{R4cY12YGioIb7P~TLqq-|Les*%<B1|OBbDz8Kc8Jr!aK*<x{2iD<&T%uH@B;nl{Z^'
    'I!?82L(AY2khAR8>SU_3pD<7ODHuS8kzYX?2gH^{5IypoAF7Sxcy7!#pnBE`J5OVVxRyMXcwGKb&5S1~U<Y>CWR_kpyHj-*EX|1d'
    'sQUXf@c4TlGuyOv6C(5}-h7l8Q8Q!3CT4sA=*}-<DP0WtP*vhCPGrt(Gf;tGF1tf<RqCO^nBfWnxtdiitVvIqL7SaMrBB0l-5&G4'
    '4_&wF-+_1X{SqUv8SC={I?p<z3_)@3V{imjju|D{0fdScvaAV$M<<~JsTQ@Sc(IrVkd9*m1xZrM!ZHjwIg-0KIac$>JsxgCu}vN*'
    'AX|>T5@hOVfyJVREH}Knl~tOiTCVxw@m&{&MunK;s}Enp03Ws~(Z*_D_~U9<if6YOe&)2!Ym3ft{eUQtZysDD!2zMmv9grUbxzat'
    'Ero^Ly_EF7?Mr@ehzAao)iHOoP;j6G<^=w9KJ&XP!1Z-n63Uh=wUBi7)7SQy@i9KN3SOEUsv9Q0IZJ#%mb%pkE1{5wD`Dn%^%i8L'
    'f>|d`sx38=9Yb-U`t);!>!ac+(3jKaeepq?`%c2#V$LC@1JXpAoasFr%*$!#5MtsO^(M#|4>DP^!S*uB*%V4!p0!X}d^XZWR0U#%'
    '!wlB&Rf7~PXSf2LoyTE%(H1~4TBO3K=U?sXD*V4|;;+bCEWP=J{zCqLgM&(!Rd2CFc#KNI<ZNFoFSL-Jaeombw51PY)-^F_9lcYW'
    '<A3Yzl}D;j2l%M2_*~8ZXoQka-=w$f3Aq@|a+4{jSD5p{>u;`Uhp2msddNEVy@s3JgS7S%-pLi*jFbO?93g4v2tB*EbMbs-up06J'
    'Ir9&Mxv1+qQj`a$7Db>X4L!eLqHAvI9n_<fo5$Bn&<}P{rFlvL%hC|X2gwvc!FXq(rVLM%=qfj&jtUdOa@|9CX}_88)-wAk4`95g'
    'gt)?$^=&@P8w0EJf<T$)pj?J+Dhofq0@E(gsrS6n=o3@eNhVoKi9why^QBKjRXp=QStaJL=ZM0M2VSgeX8vMy?Kb>m(S4Sk`K0P)'
    'eFLIbaQ>oH0)r04aNxrx=iFJP!QzeCLVTwQ;AuUi&$Q3EV?d?6Ur(dQ@hD3t=zb`gXhYaI6y4IcwwnOB@S;W0=~8Nfm(GwY`*$f`'
    '`J?i5F8;`&f~8*X;PHjMIifm_6U#0PS6(WP7}Sem%Z$I~ER(1cs>@a_yq^(g|1FnxY+x4UPjN-K<p<X0pX*=wb}^VwX9{PAIm*(e'
    'oxT@}N$Py0BW{P--|yhE7^Ai<QEEPt3HhwWaY7zOjahTw>NpW_9|-ohn&aA3wVKqYC>p@kaV{D>tS#C?eGt)y%f*Iwr!b-_EtX9>'
    'e#;dNHRrCQJJf#S9B@Yi{hb{MHyR4ox2I=uv5yx62h^iTIc@Gs84CQsIp9Q_-`$d@RG~#LYiK7|*v|AAR4Dy_u`At5e~d2$N2Oog'
    '?Rp=LH9_I7gOvdUF)cEo8#b};o)-@H%{bE|blHtalh;0dx#v60TSl5c>Y%Aix|nPaKzh5cFFSEe#3mB7@i%YwbLCp|^&HS8d;6tK'
    'NYG{SJ`7`DJz3?-3&1u=nQq^-=D|mPwW%5W+S3N0(3@2&7o2zPF4}vTxgPy>1#iqcT-tCD>=xg|fdL@kF^9?OzdP(CjLvhGq^ft#'
    '4)PrGl7^&ue4NHe-H1_^jpmHI{t!1Ey!f)!Z~H1~>x!9w3dxHb_JL+sGovROSna3Z_4VIcffTQDJLzZi|1pCLIuUF<5+kZ=%S56p'
    'dW+jlX<~PA1;7hLK6nlaeX-y4Y7;uR&)rB}yxk@vj7;t)21lP8Aj6K!rSZ4dqR0o&cEncQcmC5oQ<GLjJ*G6ArnjRrlv%_sz+%XK'
    'q|PCGO(>J)9L`W97|h7PM#recg>alSbp$9b(RYQX<U*rpWTW}u7;nzR$SxLeq~)^EybyC70IgF*po{<OQvG@BM_EK@_wZ`ln5`B&'
    'm})OF2p-|CfHz&|khhwWn0vFFFb>z8ehT=|@?xm~QWhvbhC>5%;-({n<!XihH6P$sg!b8y!Gr2{xisMdn<~z&#C)q#;8!EqD9GW8'
    'mFLR@^k|q?yfrA%QCrYBILu5iXuO!V3BtLs%TjY81x>es)>|@{EIfuJ5ZD+Re5PrG+Ms&i!#wZOTk|r<R~w`zK<Z=+ci#=;(zRBm'
    '(g@mdSzyn+@7q6%WVqOTNvh6thLGfgbpo)}R3PETp&d#euShEhsJ;>_N0{ZAGGj&Xsdu|}jispU%`s1ZM`F&<+pL1==6YLBme~)B'
    'dBHYk0LZhlyb2ZR>$3svTl(n&g6KMYBq;EvYaK51ITnd)t1tit@`-}6*)|<UeQ7iH6}@`DMxS@)`Da^b_t$@o{}Xo@@MrbqhBC+X'
    ')5sm$shVL9Mn@vQsy?SkeaD;uNMv9`Dif$@Cr2$#syvH`98CvQ#*<<nNi<AAk<*W;y|^#a6R79&a<zy_)QfSQSGb!C+28to4JAq)'
    ';X@Y!`|y4J{qMM7qp>=k3dbG}u63)840;hu6)xC1JyZ+=%Z4Dgu$PfAGK0HTg24RhA&#;+!<Hh|(s?V$BGYkqXGFbiu}&F?@65JT'
    'O}yF56<>ai%EK9kSM{YVt$WQeZhV~x-G^j#T-KWe5~9I*B$cP$wOB@+PMbH%o`<f;b}U~)`fd&f2N~#g*JS}sU;gc@=eZg#lG}oI'
    '!q)es&6zsC9~%wd?<S8FphkOYoa5C$P2t!m_%AQn19Sm7YvDx$Hs@mKYM5zQS8hkqo%!6UF_Ihxq+$5V$Xqmh3}gDYfJe5x(}Ywh'
    'q4&ushiK|U=|uR+i08upZe42Gut*(Resk_AEcV7d27R<T6XtncddZzY6F#SbY7^5s<U$Cy+~|iwRm$1_-Gy_sdiVh-%RP*m*2Y7<'
    '4NMT-B5n^pQQh)AyrmF+16Pe%WMQL&FpaU$dgbhFR{`QPiFBrjHh>pT(;VvW9!$<rFeBnCv`JqE`aa^z_<+nL1l}dG4Bh*YB|EVB'
    '19@dGk+@K(6Ga%US8oPy4-`MT)>`f0(w{5w!FTWMmrdItNoh#R=+s(2o8#D=jzn1P|2%)WEcHlIFrsN$p`DxO&%Dt8nU#BDMB(PZ'
    '!=`40AkrqpgYCVuI0q}=a3Y-5#=~c-3xCVs$P1@<46aB3p|(M>U-$HP*al*g<IctT<_H;Hv0~9){i7?C@^o6+u(WLibbkxOd^ah!'
    'D^w{Ol<|nC@cIva7Y>`;OVOQoTeG?0z1sa#afj=Ale<BwET)8O-qZ&-@Q{7&3o9zU_gC__7d8<hPxXU{pNy=^rXq6N<G2^o)j&?k'
    'C|&tq<G`=E-%`J1plTrbjRa&Me|9$c>`s+M<TP)JXPwl2j=uOFTN}1~Z4Sh*{0sLWDI$*)TNu`LGpQ~@_w8sd!T?5heRbBtzr-aZ'
    'uVa0YxR>{ZOC56?VjaiH%q|@F%<c`0-Ls=ec*NH(u*AQlJ=rn~+?cXl`{FA>C2?Ho4b9PQ60qjLfgXUq$cDx}J}QW*`N_NT%IxdN'
    '%f9kItlxsCM?<90`Vbu-osm~_<A6{}LgZ8{VgLbFfn2A|49Z)t;w0LEtMF<?7w#GJP8rzrJ*CZps=GZ=#foc`VbJQGh82d@v9a^z'
    '%~4pDQU%d9mpjv(g{B@(otSy6MF79WzFiH%3drb@6DSEEOMEdrL4>Mc<iDC8s0$jKpARl@$W;#3cCajhz!I~V;rL5{Dw{#JuWGsA'
    'pXY8`4h(mrng#YE0{N?Sb0wgL+4E3kp<?nk_;)by5d<P`?%2`&9oCm3hCd5j<8oC*`7X28sPS%M!+U{o8>BT4VI8_TX06N7D~Ve4'
    'U&HB<^btL4>U_t%1AIKl(zjD<Oj;{+4Mf+9Vk~e9FY|#S9qLwaP@DU*D4`vLDYpdF1_;v!&}l<h>3HY|y^-_ee!+sK{lJ@n9NbAb'
    'xz4cmg9A{$VHX|Rv@bj;!9a9iFSfz-ZJwxW_*ZeEgu$=mjhL1?wJ_W;5_^Mi{HgYmRNQM&Lrty)oo4bqOZk`Vn6>)kxV)aDC;`~}'
    'CVRUv7GX4OtoSVX5DP%GT_D`we>emTc3&rEe5H~0sa=af>H0E$I4=p+0}7e15@{%U60LpG#DV_mO(vOlaPz*G#AtJ=$@s)37g47w'
    'wjY95@Ow45bje*-lev3`8{ogTl0%cLe`0BlMkc@bu6zCh#4H7G6u!8uU%z2+_5G$#Tpv1uB?*5s6tH!qel4;I!9getD+IW=i)@uv'
    'wRSWxpIDh-VBq0fCarb&sTBPUtSdZmlKw1;FKu}_WuagJOZ3GCf=I(wrqwq5Q?M3x^gV#eDRn<GY$=W~uzsht+5y2YH5V9Hpx2r-'
    '3_WMyxOzREJv&=fsxs)XI^&9-ySjnSg!xuAMd9fxYD`BL8#|z`I@8h1-bEM~{hV-nqil*=5@cyMo^SOVZD|2${wqdYmr-O!)*%F3'
    'VQ&RF{Pucn)gmz}F2HLF*rjnm_d*7FeEjRg1U@bR81z!xi&Ox#v|;^ZQszk84I1iJDXNa1?RIozbHN|;C)!*!pMJ-v5BTj_%ePph'
    '59eM@$)7gN*tcgci)WP8Eel7z3H1xYh8(`MNFyH2TeW*)$*O*@tCSUaq@OpQoD6SCx=vq?Dhh#)3t1zJ29N675%s)zyGIut3Q-7f'
    '<6qL|;eCV_Nor-3wYTPAjK99K`ib;?TS`gCLAo&pQL~gQ52N>-)u*ukod3gZ{gRGhF&`7dtTM5AmuO-9S-FV;A>BI*o^31t^op)Z'
    '1jbc1Jqk?X>?O5U4j?A0yzQA1hYOi6YR+d4Q1KQeXyzBq!4;z@rJW7Nj$a+NKQbyXB)L@s4J~A`%^GTCy;2!b&G6cuje@Ux1?t+k'
    'F|xq3cD8*wC%MYj)F3177xLqkK``(9$s=RY4rXrO+8EPg1MELAMn-v;>>MFpxNoqTWNVZ{hp{v_(FIT`CqO|6i}xAx>rQSY)EXiQ'
    'B(g#oy{V`JUS}jH1?&U+>sOSmKvMc5tX2;pQ#g--xKYy@k6ShFxeu|T2EYf+QBQ@#bW!R?A*0J(wdx=`J(r#yzUBV3a&8beC*UEL'
    'p=t)KNsxHuO22mch<MPx-g@d@%Aihaf+e+S?0a>mD}fK0So&2{d~blbqR`;2+`(dW$xXOVI->cnxxh?aq8vYvhg~v6f3cXgAlIHe'
    'wO-LT+R>O<dBw<vypia3rS1DcXud|m+>}Nt^MoQYl$sy~f>6hTB)q%i`hHa9<q}d1=e2k_s(YS-+5WyY0>L_Q7N}2XEV@QOjdR-8'
    'klL-Bm$#FkzixI?3=e6bd+6?l><vtWaR|vYK0+3j(;W{0!^8js%M872F(ehDwciQT)%>8YRFv+o&4xj&E5hqOIrH1wC?r_ys#%r2'
    'Q9(=pe3G~ogi_J5^TMYEhdWo50|@{#9^`P>Q@rT?r+LCm$Xc5~Z3$JV!&OwE?z;d*NU`7p>xR@bBR(blk+xOcRyAJ{Cr=PYcc$1W'
    'BnkwOBcYcBnWP0Jny2~0NbABY+XrSTu8%U<D16bQE(qGVK>&D2rAIm{w;v9M2~8@8E`1<M=9EW{xiW7_B5=W3rY1p!)BL#nuBIk3'
    'nr+pq+h#bDbOTL^=wSnjHWraAH&yvIQO$mFLzAilDO1qDN!%ZnO(*T9S*x#HY?5l7nd~O7mCG38o^UV6!Bp_zc18^C4pLb3b?%7#'
    'kq>@&T<&wkkBNFEM=JoUB$)#We%~ClkdTuJ(a~o_#&gyo2r&h`;;vqxgqDyY<#JWrhDmIl&<T?I|AA>vLxOAO?X<Q-*B{21`)T;@'
    'H<p)y9*J#gQ}aMp3pagO*xK#;Jg1p~gKc^(79VS<Y=7NZiE7x}o{qXmDK5M(#6%?5uHW``UT^FZboJBJC!E#FWA<`YGlNmz0#~OC'
    'm>S(%%BG_sl-}xUno0vD>BK}jpk#|*`RG8y4qAYM6Ye-WFNp-EjnhIXpW5uWaEy)n48%KUCvh7a2V`W-!u!G7XC@|(0<-$D@Ys8&'
    '0B4*H)`G?Xmb$f`OESlPP_YFQF{lN_@8Ig$>jp<~EKpIbhZVj=Gmtu$=MN~W`s@0C14zyc{*JKNoy-1m3OkRyq^-{j{%zf_0k}(8'
    'wqXhWMDbQRa<nO7?oHaJ@w3_R$!lZwUfZN(xy=CkE6}iPNT0QVzi+WMx7mPJ#drgqYpk@7oSD{)niZy~Yj?IsW!k46D40{;gkyZ7'
    'U(xfh@l}F=z;A3KP!D?bG6t3`!8WOP(xE!8z0eroN-k`FWGYW*$^5qp;L_!)Ie5Fg@3yfTAj@xvN|T<^VeQ!|7T&RQ$KJRu%31Pe'
    'd2o4IHc&s$(gn~d09_s0PK02c`WQdCgCXng-6`<-q<y$1nX!(t;7Lii{7e3<m$nn|<`x~wd-*Dk>XJaVZq;A3Mi{U=<^0%DIrH|h'
    'x)~A%q;LSrl=)ZsQB{Z`w>S(sq957Ife@-xV%dTO@IcB|k2tSOAEZ*hX?DchHzNPy?zM1eJMbh^m7`U>ZG`o%(jKPF(7u}<y2-3^'
    'p`b?_AG@r}4^*;$XDvuZRGrb7v|WA#TvcTL3MW?%L2%2y>)1uRQ~yXQuC_6skq&$FO=!FTKQzXQ>OPY@ZEslNJFlrnjHAgY)U@tW'
    'rS}XlpS5U&Yh~^;{UOO5{rvsG!U-nv&>nnD7!su#Hor3%!!PT?12%E9pE7zs9Gms+f&8yGX^Iui5>3wEECPP*=`5!tK@sC_^Rt8L'
    '7;3i-gf#O9O!v&s?w%!NKOI!aW=e{KL@)mVt+f#dnUoY}*LamcZtWU=8Yaay4Eh@&P;CJE@~{WpRd7_pCMoO$BbnvqaqPubGuo-M'
    'Eq;>?`Yn%WzJ9yZIcJnk4t6A{-wnDvz_hGL*7DeL!;M8!Gp9S|u^z<)nnP)Y^?jBG=bwb2#8kJ>xZy301if-Z+gK4Sd|abEsWZMe'
    '>8b>iSr7n(N(6n1*FUN5XFcvAp^?`tFsyy>tJUj}m=IwG0w)YhLf7?obH)}c{S#qqZs0Xrn80m;0WaUdxAuu(xqiaI=Q{%?YtX|='
    '<ve!THb{hB58X(p0PFL0Th>>PafJ@zB}yr&;(+ZPsQN!(v-eKc{aWSYub2d|0VosMrxFEaCloY1EfuEHu06pt%JyZg*>u0MvX$YU'
    ')t~>WGF1TVduF|c*-0(U?+Ub_@%d7EB^lf<L8UIeK)&ywOicl@I@Jf`9T>T3j?`-`v-Y*SgDLvRHSK^V`8uKC5}-zYG0@hQCp{<&'
    'te;ZdiqOax#twkDr0nx~f~h{H|NahnvQa2ww8Lrr_gyuQK1GSO2-!5_?Gz`=g=7%^{e@7%*&|p>F(89jwZA2<qqf=TShNxehI~su'
    'cv?_!?@Cr$QOA{*nZYsry}}VtjNuX3|F#uoK}yKQ5V8`#QD!$93)P1p9wzhAR+<YQn02ws_OI|r$Bh9;!Fl@$RJGcvj=8iidn8m-'
    'Gp!8|>>}>l!cROnl1sz5mqIx>^j1E`(bxF2Qf9<;Y6l8Xq09!QoFBK3`70ED;1r?7@u(Fi7S)Kp@1?&@g)p-ro&u4~CC$v3aRhY<'
    '3S|<`dT_3mB`f(u`@}>A-!^lz`J@6vrB{5MN$^SyX#a}Nd<3!8HMy2%*0cVQ!#4Cj(+NeWaCAlkHnPc4QHRZd+OZk6NjrWswmE`^'
    '>Ccp`__;K3osFCKjA`SH_N%}Hok;s~%Fn=CTi?CAiR51M9X!p7dV)M*QFTMQh$i7A%Z7m$2NgKsBh7(uL0D+~nSYvgM3WJF9x5P!'
    'T?F&H>-A(|ADzVA83i3i8k1#J(^dQ$Z^NTS_oR=R<Y_%{Vz^c_iihk>%1wp8iU=;LHEFD!hN&MA2!76fupGEp+vB_yg2u%d)~3&l'
    ';D+yiI}E%@D~ra{WfQqK5?D^zBTJ*W+FK4$_ll$FvT%C;<Q&T&C9~+Gc;LfGL{jysHlQKr-5gpDJp4|q|N6pUT+DA4tC+b%-RIpD'
    'GwaEi$+?!5&dFL(`R>6su_WiadfDA8J}MnDPMbLOuP?jlF8MKevh$~?Te>|Pz^&7ea9jFOpLT>g-6UiY*teJuZ>}2=3U?0c$69&v'
    'yXl!#`J0B~SfhzRa{uUM-RHEbZ?5e8paBk!JBy(Z(4h`j^)ffdmn3gFUj8wnHYry#7XJG-R1Hr$4yxBRhZ-?kvF01$XXR8IlK{8)'
    '39bZ|={W9tv<+hc+<L;Gg(u@a*%$3`r<39UcajMna_43oTy{-^!V(mtUXAYM3AgXRmxZoaK@LtsK|?9BP(WC2EC+*ff+(kE|Kl3@'
    'P?my|rzs@t3t*6P@dK9r*oOEVVSTtx!oZLDmJ(sFMeBw<Nz*56u*^I7JfE8I&gUjhndJdJ9*$=iIX_X6yZ|oBV?Lq0z0F276Gh1~'
    '9L3xk?z`!6zI;tpN|yqV5+ZHUBmsrMYK$C)){zLeO|i?A7zz<puX+zIJmM4wTp{(2#fRWPXtdqfYKOtu>zSqq?a{3Y2VKI<yo<y$'
    'bqdnBwM5EZU)rtr#1}O0qB0Ok=TCR|6wk9iM90J?1w!OsInIH{Kh&_{)>iL{yN?0{SkhVZu-hX^vdBTBqfSw^0y!OYufIm#g(Jg&'
    '(0=n>8GkDXi+oJ#!XT*ny6Ugp5b%8#7eC6F@`8Tae}x-CL;69}2?@t+HjdS21YH9q2NN3Wh$rskP@t%H(Iv@uDOwESNHrZ27z+ft'
    '6rhtG%N|i*0fv15hJ%x%=)FS{pYLh>LZ)8ZTTnNTYKg6lJ|gsY-6`^IOMNil83H1ChxjQMDEKuytB;9b+$5#SqW;9CF+&{><K)Fk'
    'sjZt7GII>y8?ZF5yPjcFbO(`M?a4VoWKcw6XJ#CnUD9yQILh94)payVUXd$YzN4jYFS}6n50w^>|DO`uhKlb|uVTp^WWcoNx3<Iz'
    '7X#ad(x2xtblPUfh;}6n;C_>AjDa_DEl^Bz|6GcL;$ld<YtwQ(QFAri|H5B+g$^GalWMwe;lI{d$tPVMA`?WGhP<aBNi`n)H};Gq'
    'vn`y0i5o&&MY$=^{$`I2EhrE@w~3qwR@tlQewO&EZ-zk5jQ3upOXKoNw9h(+-}{?~9Uk-}Z};cc$S#?tW$k{NKcvIGCl!GT<}?uB'
    'cZ(LGoH6CdD-vbQVfOlqzWn7`WS-57L;N20oe(@nH<)sY5=|k$O@syeo+{GVU!LR}t_d+0xjs=EgyEiv{r}xY+hzQZ0iY7picCYr'
    'UtDdrjq#y|WP#O$VwPZC5@K0~UH|#lHhyzoM7$vf>pZTQn)_|LS&tGAMk|iWi3hTb3vkdB1rS@Pa8dCvrV`CWdGeJgvkPS0r7Oi?'
    '*9C3cz>JNYSQCB%UHbq)kSB<B%VWc)#cqw$a3L@2)>TtEdH-LuIxb%wyKDi+Y!$RJvUZEksipL`NIXv#XPZ0D^1-~GRZ>)Ih~d)?'
    'VsizVey?P*-#Q2;0uA{=xC!L=l_RBEl1(2hD*l%O529;RQ+U_G0eZd(_2nbFpgis`X_&<~QV_Gxorccpp|v*dRUDxT*ug`!{6y7B'
    '^O|pDvK<HbErBsUK>UyC+N4;CCG`fj)Pv}=d!*kL5m@u0VPe8Ut)u3Ka*=I6xz(6~X4it4lHK6V3M)4fAgLmumqzNa(iO!Vs_*^P'
    'Q)R0c_0f=bR@qhM4?W)1iLLYEI_K9~wQ}Lk_Kkp+tzUTeH%FW&b{m6^rfAZ{Ts5y-$g#Ypo#c9lKP&qDXpU!a=+Pvq_Ni(;|J<_-'
    'B&drw10<8CKqnxJn-z|2MQ(FHiHst-spQ_&a~KS+7%PLOj+Z@R8@N9pwC(zLe;^2>0)3pSXb03@SZPL5&^+FA;b2%maz9s%TvaOS'
    'V;jxp&af&T9n4RJ2vu<_!iDIm5%1OQsUSX8<`T|^a8cKIrvZ7PnxeOyb8e^clHN^&Ni{{#wl|Ew`E7@luvyE(duR#3g(H?|oS(Bl'
    'CSdURfEs=r=G#QN<BC=d4t|DD;0Q+2Gu8SRV9R{{1I33@S1rFL_n@aon$N_9iCnflZ>S97Q@aJmGETbz6=$(G9X%)ubSxfB(tfp%'
    '`C8^hxhr+x{7@&6{L1MP>?{*d!2mF13}v&_l9DJ^#cy9^dI$2P1Dc5$7dH^;nhUxY6EtgyAH>Ftge{BrqL>+wt#p%!49TQ5g1^i&'
    '$=Ds#JcC?uHIIb-hJ&{bnI8NN&@>UqzcI6`#cicSwN9Hhs1;-(5hA?qx6plCfdVPl_*NFueE>}%+6NxIT$jq-v$@L~jB&dB`giIi'
    '10Sw@#VWNDfVYZa>Sy5Ydnx+}85n8j(p9zNM`g2J71b4pCu#j`1D`B`5lSHaq?Gab=17z%R9+=?hYm$aBdce^eWIUJM8Wp_$yG$}'
    'EO}r-?_imJW}5M{9LMU2ph9>HMLHnTT_Gd=n+>R+V+vuo=@hdoQ<xl6nkK3R`=;;rZ(;^*M4r(E!(+A5HOV6ebS41~3Sw0ZXRIR9'
    '>!X#QsL?gdQkdW$gA25XD@j5a&XvH~l8YqiTFtM%Y9bc`JJe{T3NK2>i*k5|{MIW|O0Htbyy+HNM_eFxhr0Mh|C#~R#wPfeM*8(d'
    'pJf7te{siMEy&RCEz;d`s2<@ng|reJ)d&u{YFv+t@DuUU+YJ7tz`E%8kr(}!(mcX=^>&9bzt@0s_i~2JLXw|ncHVnFosdBp!=TIa'
    'l|(Ty*_G@o(WA&L`x*gf@DTus;4=Wl&k2QfxzOtgU=>?)8rH>IvNfysG)Y{?I-bM?i4aIaW(l!=$4HlZ4eN3NuEr}8+$43?T;g-P'
    'ZY9a$KEMY7S+5Vaw~tZsv%Xs`;j)X`xV3!qBUbZ<p~l~L;iO;wd5F<v{K|q14<ZTrjneT2>6<#T2BUvoX<bSZ#hB;#RFsO)1$j?@'
    '9{F|K41WPZl#2GdGztVhhZpkr=T0{`AmcHGK)N*<BZR2I)ie>`8+U==TZJQQ;UUIA+Z3(U+Hmug+jW<hL>MP~Ho#PkO&qPk1px4+'
    'mqE*3!Gi~TE!27aF4ND%?Gi5YZ!M}K4>`XM$c-|Zx7Kt~vvAhsrRq<~M9M?<h6DCf4IS;YPiUrDV4KK#l;3$!4Lz-Im3I`l*fjPq'
    'z?h<AXv_d-lTq{3kw?`w^C>RjKpx*>3lZ*tDwu&{gT!{X`+J^|OM@p!i=#JFSo;1`LX<@`5<b(Y<{&<=e|gNb4hVJCdgITU^0HW*'
    'mcXwgvpAitBhY7);g;;Tod=V3*fT+cNmqz5Rz+&@`+WZdPK(wF-GiI#JFr?Yac{Ro_dtaFt0^`lZq3pkycM&MfM?{dt=IS09LnBZ'
    '!J|EFbY(vYyoU3q|B#(A>`sSbGYu}t%kxx*kHC)>tKUl(QNt%<jZ<)<0$!JYvq3aOiDgz>lYYT_@=jMehfCh=-8g&sL=gy38YN>-'
    '3KZ=`OYp%1eYJdJwy_UPBu8vV`m^uggHFnzNTF~_0*ANDc?ZRbZQtILX*CopURs(_DL*5|N>mY(Y9J!-x>uC*J~FWiSIG=Wn$`TJ'
    '-^=CmU!RxN$i9F;ZcBCFd@_)TB^y-Qnb4U9VUEN{4U?s6YM9R^5#~~g=;&=|_Js_69Lz%ld?Oy1ZZBNz;t!suVO3zk(IO)T8f8&<'
    'j9zjs%!G}z8pG5-Q|Ur5?VjL+JVKgJi}0BcQ5`JQ#^t15AMS<-!p|TB<;LszHRBS2)JU6+q_4Py{}#PrJA-SIvn%f@zUj2oI7gos'
    '!4Fhqk|Nj($j;_CZk+Q0bUr-B7W?ctM^=jr(hZM9!CDQPD-97MSC!XX5A{A%2Mq#Rn+Bv|OFT-9n8}v+1$l4jL8EaUvgx8e^H4gq'
    'lQ)}-X4?npNU<y6oR^44beBPT&op<akF?Dg-YkrOpNy+Y2(#pFcplF`e`iG*{NvUux@%1#fK9FbiV05c#15cI{!xhjTZ-JP5WP71'
    '&-F-4T*+#`DrE@a97K<Xy$~{%<gPR}jry9K<U%-!o48d3MTsQpCln)*5mT+V=EsgII>WC5)C*+vzM``<kd$gHRf<H|7To3`NFwgO'
    'h<=ya3L1EKdaQt6>l(nX(=E<^<b{Q9CbznO!_kC}1=c!W(B|K$+i_ViOAu#8-K-ptaU256jvrx^d1!0*FNS^4<=Bk4TDQGi<H#jE'
    'F`QCBc$cGuAAcHP`;pi&Gxk|s*hOSLomfIo@NT#^PDloNSt&ka>t^lZr1-p-T-b>QkmV^5L}^mUkfe;0=lh|2dOOr*#(FOAT*@Hs'
    'P%DPHVOOFJf%M-0(FTpEKR>kY#~mtiDhD&4fre!kY%IBg9Ed9T%0_LJ@Jw|IW$UMxR5{Mayw*;5%auuJA3Kg^L*7xq!ROcsZZo>4'
    '(lv%J1&cy6z1NYo2=cS621UCH+GEu~r|f{N^tiPw^V&4ym*$PG74iDnJ7!kMf!Nl>mMRLzGt<wXTpT9t%tznCKMgE2=17R0v*PSm'
    'N%<Sd9f1(lC`7#ct}gcib$@VwoOiPiiYGP7`IU^2N6?L_LGa+|HBgxM`kez0e!4&kW5i;&$BN!t`9%CAQHp?4kt0$eG?0R6X*^lF'
    'oJWT3V@9|Mi^{50y;IyDHD3}zE&WC#)iUH5sAS7$u2dMPaa6*WDYW!0zTVWbmFO&4iWMA2<C->7dQheyFTIwXe&^)Fc^$D+8LrZ@'
    '--MjQE}sbd4b+K^Zt#Y3yopcypw#@JG0K5Bxrtri?%;l%?GGQ}mvJ2Thfw#<mEP*hZq)-)XyWP6P+0f2I>qOS_d(fwV{$+PRTHDv'
    'NIxQ%luN`RC+BV_Ens(7#W1Wda(a|wYDbkeI)kA8;Z(N&!`{6hWC?m{;@8Zq3LufV64&r?gc*-nw4E@(N|idrx=mU@J<4|j!}&zM'
    'jM4Fx7g)ila#`RnR2^hgJoT9;nk-o2w2(xm`Ze<oSWJw@P>DX&hu<W2jS&Cg6t`dpK!MJzqOvbkcY1p<r~6sZ<Sd?!rKu_`L-#d('
    'l8hrgbA@cCHSU+^?rOSr20^7&y<H_SHCeiue1?9xLzN~QS#M2Kk0n7l0GQJ&w4XY+9J2FG&uc8ZJUXsp6h~++;5RoMefnsfI9*$P'
    '<YCo7Y!B-@!^>*$tyDICI+P$T{nj{;hPw`9n_p+23afs}X|N<j+t4s15<yYj_4>qZb&{XL>nA3izoYomPFfeSqxD;&n(_5{!;{F&'
    'Y{f=|lf5?6d)a`%q~`l`WcFL*gLJoMDFhjb?_=!VLP|-wlCE_+fDv`GS0PC@U{o=6oLh&<c3szyBFcao=>!ahmuL~fvp}|ofXh*r'
    '74~TI?lv&mGs>}tpz(_9y6?j1*}3t2b2y3Kl}da}**t*azRw?B=g2*|IE-r?l^VUowkpN;l#(nonj1@?ae$F?thO7=`>OH38635e'
    't9ycJG9Qg!-a<`C1eFPjm}R%o1@0nUdW`bGms%CX70`qdMsh4AZl|}k>SD{0F+~7Zlm}!X<vio8?!D^#{UZnXmgTQPS<Qn)NsK1M'
    'byDAa?^L=*gKtntW1-_#OYsw;ACa-V8gSvHtBTHhpfB`alxXStGK8@EInS~^h8DkoDh%CzNtxU)bY_K#`Hm#SvB0QHuruS0j-*rv'
    '{Iu#cNOy&p);zV2(B{%Zdqw87+6TQN>olS`iIOR`RK>q8p&$jR({K+e!;{u{AH}>+R%WhtZyjeqw_o(Tq2Lx0c0N4N)>_fhgSePp'
    'S7Gu{xp4ybBLmaYG;(Q&@}D-$+eGx4oQueis*dZuof{hd1htEUuur1B&>aOg^qN6j6_By0UP><WUwv{tqq%;w_qWyLD-Asj8>8S-'
    '<U+t|u*%9573u<!bKS8t_eH6ZEKBJd`QnKOW<8y6lp)pBMBstx@S7!|a)cak$S${&ESM0hG7Xfh=4V&m&#lSurr|Z_SsMCXeFc^2'
    'UHJHVcO8cnBq2*kb$pL;pB@o^mxuBo18Acj#{XI}Nl0N@u-92HR1xUXYWJ^>{fp=w8g{EQ@D5O9p4t?`g*7{#`h|>1q~Br6Elb0B'
    ');^oAu~zn<6Lf6w*ZvkgJ=Y0v`W(L7v0b47uvmMhw{*OH<R-!JlM-*T{r3xf$y3!69DGI4m$f0pE~uUUFC@XjX{&XrX7mO-EsSrE'
    'aqV_?{>FTjxuLkyibm1RGPVRB3p#*gs+yw$gJl9_Cl@{kN3__60Ckb815*4F1v#tOtLtaWh+Cg6(>L9DX6!yHTHf<I<k!jeyx^Nu'
    '<;;}^3Vkxfz_c^imDZk62s~TaE181b7!c_}C6<QN#@&8VYQd4Y_<E(GS=S#_Q0Jzr&@TH1vE@<quSX69bV5+$z`^)lJNWkiH@N!('
    's5)kP>=;~SvO;6q8)CX~g)lj|e^8hf_X$B0&e`Jw&2n1dN9uoVn{sQA-6%Rb`Of5!KmGqbd(hv+)kkF2{g#0CK0ai1cTfo)JYsZP'
    '=evmC6YA{7Do}zxwBhk0d1PF-Jd07+A!?RXxrX5MHX;H;c6T(qlJldlP!x>?$QWrcYym$3?QTRXCP@10pU8k(CfY4%uCX;E-j?jZ'
    'ZR8HU^e!uNV4k#q-60f~d-GY3#It)<Tf0!DvRKu_pM%NIM)fnLZG|4Mepy>-LuX^*&Y1ETz@1jM8dJp2y5(3Vr?}*2*?kYo0)Ux-'
    'KTp7{*50bI(hvsjp4fNUvpkF7a>%&4g{YX*hu5dn8w9{0%%t{Ou-5*D2r_S!Rh<|2fr~T)pzL%>xeCVW+sQCG_`WiHE4k#AQ+Kbe'
    'Y*I#sfcR?3O_+YzE`Jo+*IX}OZ;;v(F4f93z$_N+_`KdJpr2#Tb4tSLUR+Tg%wdrlH6ia+03?aXG7l8R@habw^L^v-PuOE;j!7Tx'
    '0e_f*li$?-4oOb|I3mV-99By`oEl{rfKR26=5{z9;;P`DJX157n%Qf2lt_UF^u7QyoOr0APOi{4=6MDt(m83?M5Ms`^`7?aY|5xs'
    'o0T8u1O@F`-<Sh3qwZx2C#Ur`qVW?%HZO3gPWSh=kz3K<h(q>`;%MG5R))*8FRsiV_hGHz=P3*StCysCSUor68MU||j;#{pg)Dzg'
    '@OsdM^w=)HVe)N`YpF%d8vUdWaVxX<vHp6l>wWN|#14}wX{Jn?FoIjyr8VSd;2yU-L$JnCF&yE8tNg74qNu!Z?QSIV=PkJTZP+kA'
    'GW1p6)ADhcd9NJ_A-nA*5W0IZBOVVMhMm-UwPc6MbdMq$8ZjE9fx#z^=D1%c+p&Yn!H-wz!XlVT89NkE(GPLReoS7QXk9v<9so76'
    'GLy~%M_Qbz81?RX@za*h%oc6yeQN|UdVJOd;&2(w+V2xcq@Qx86amFI<{X=u+xrp5x3P+w#m7fpiX<9{NmOSggEQpg88t9BrM%^X'
    'K{PT{V+1f$96C33i4*7W)@=k)4vVeS0Cl_~<(myd^M)-)UuuY-UdDVV-oi$;fK(AZ+X~t*86DzvsODGNWJrg2wQ~S_Zg6>Mx`_1p'
    'zk{`5{2WIRNb8!cyr{wryB{FJsf%4V++=^K0BIDs|Be-QHr$ZjG%!e&3!I|r#<xOo18!%-<WN2~ma)x<*7n3L)OtnivV!-3w?kaT'
    '(0Iz>e4Xk+GU1^g-4J5<2<j1WiS1>j7;@sh-Dc27cx{omEJ_?5&qf7E;)=14DUeM2MIEeb==O^Dfh3s<fYULusL~cT1D9Mkis669'
    'Rg%CYLOepqlR6NULSqBS1eV>#b8~t0bwwfaP;ba6Oer6~*3$O`+TWaa#Xdr?&L`&*`oBm^?jWAbwq`rI7kI~@NmfRahz?Y*6k**2'
    'ha5N-R+3mR-Be+{-@o{5S92!7^EPr=C5M@M`*v<`6Z)d;e^riv)H^(so^BR^@zMJVJHVJEZ2(--LB47P;su!LT)YQ2mxgQqx?_lv'
    'KHy=yB1Uiw-E1gGr}qZPX>BRfWmJzP7$(1M#VKN`@tUVbGG??+5nG|gc<@<d!8wSYU232NKX@0N2&7}M!Jg#F&qZS2g|53K=`h1|'
    'mSa>lhpNa6I{G=Qz%8{6sMpTvo%30^$Dt}(a6wovy@}AgK0TmxcqGNDA|#Xf_Lg*iB8d*NO1M;A3DFhL?Di&&b}tQzJL-d~RhMc?'
    'DokOJAdKATxn>@5F3oejwtTz;k7H`|%&IF?DWl8W*nX)4yQAbjyqhBqw0k$J5s>3k8@|X^Gf?*a{j3W;%6;`9ExcHaJue<TmeydL'
    '_ZKG^MX~%TY^B%4`BpgEfK?_3mL>)CH=s5mjfT1cBk(MDK{;>I+&ZQv7VUk38x;~G9g3NrdP~Rgl;*f)_M3Hb?95N__MHr9^c807'
    'ML4)DZ6J3~_%j&#cKr418<OBqV1u2Y^vxvnvOzntMeg>^%@Rg+hs#5p{8)h1-ee@qCVaf|@TwasjL{Bn?FyV_CmCs#(mhi>NJvPj'
    'p^FyXG=f-<A0g)qn#fR$!2jB9i}V<|)LFsnvrYJWB&qE^;A%N!ijXwMaAQb9C*U?eor3*hq0Naq@mjgvpjB{3z0&A8>nVMdWuGzg'
    '7y+kanf7~oG6xoe)iB*>TizWe0tDIs4;*eQqA5?6bFCQ}P0say)LRm1>c$mW<=P%fIQ)fOr|9ZB6+n_iqS(rLCV~{w6d&y_QG@QX'
    'lj)G+uPW3;+NU^A!qI0?V!EmjnUe^9g)OlfBv$k!Y;s3+6Ir)$6_VbR4V|AEv>(PDc74bUg@H5lz8^9=tQFBRHij4hIg0suD+C1M'
    'uj~-zo;I^u-e4?4dMW0)Wvul4ZrC$eC_RhEy2I}VR+Czj7lf7*t?*`M<4im3^l(fx5F;OunA=WH?>b&!;sP<P1fVKR+MY*`>eW^F'
    '^sK;mpe5aJkIvdKx4sB|M9};}kC=FYC_2)qM=@VBEnK&Yj~^UEVTGg*F(%L`n4OI5GHYEB^h)W+&9A_!Xb5f<4nB?5W~+;AM*A7_'
    'uD0VNXi7q^$a&>fQWES@QHrSCRus7~Ek+~cO@L{(cFZFm5JQCM#g+GtSYL>v!}v0N+w~ZJD*{z2Vi;1t?S3}uo%=}t3M^w8HT{H4'
    'jygp|M0782?gYRGCSL53^i{rK2z#YHo1)n_kCxugd=p&+z3JgpOYtS$|B~Wnc5I-=dSN@f7GRNbP)bO%$;h_@%mRsk^R2Va39Y<P'
    'JI!By=ktRuA69~`w6e<3EHuCLDJlm=yf(S#qpRuv9Md%Ky?WtJ_i&3V?qBN!$mrZq5~!U>>AzgZ{yy4Oj0uejVgJ)J(UCtRipLh$'
    'nF2mfi>ZQCt|?F?PPolE)C`4!5E0s-ciZShi$B#KrGitCLu1Wdv@4yME-&9k@?kW8-2UU;Zj`k&d5mX9W0I!3+VZdHzheVH>VO?v'
    'D%aG9e1qL`p7ERVsl3sT$bGrxL77Ra!2vZ-y+z$&Cqa1T!yoLyy{G<+#)sb+FX;Xpz93$Q+k6V&JT!joC<U(?r(VKQnVc4iH{?do'
    'd$XSi(>Al!$0u3qnY^n<7ox{Ahd?ZDY<%EA@PJ71J~pZVZRLsecRqTg1G%=%vM{x6|LVgYa3+JR0DG$o8B3>e<yQjS7qWK<Wn7z5'
    '(=xzh?z^V52>cDCUS8%7j*lp&)lIOO;}Nj9dpu6CEC{@p=BURD+G?OxY>t?2uk|~4GBXTwE%9pe;>#Re$sVXpfN}i~&7{Mn?#ev~'
    '!%#~IfXhcn)I3JemXJEs9g9G4I%RIt8VkRmLAR!Km3sxi&@EQP*)YU6@e&09tAIf#l-&hF6)7}y<n(V4y1g^PPZQkoFp4{xt;)w|'
    '-|tTdOf>alq-C$a22P8Y7KV%O2VbjI$uiZ%FgR7IlF+`Pa;_!C4Y?noyJkMovzq>PtCb=!AN?pP<7;xyt%HQYjS#aq2A43I%u<<('
    'w1}P)2>}4^(}%ioDqf~`l#WO{KomuU?to?1+Vo=%kw>D~Q~6^dcd|Yb>ZpM&U-MB#JC8eIw4(kg6r^V`@DzKzX4`E2l7~JTtRLh9'
    '<uiD8m-WazRFNMB{@<eI^8W9{3);!1b}xrmY_cDbYFM`iq<T!160)<zY>s%ub3e$|04lx$7GiDJt+`&erwyM`D+nM{8skkwdBB*d'
    'dkyl$hl18g&ak3Cvxd;syM3JYjrMCr#H>XeN>zH4<lm?~UFT1fWocl56xTH^+$zJ@6kCzvK84-mr#+O*g0fD_knzn}k-f6{kuof?'
    '%V*DMEwr~(lLLr-6rxPn0VAblzK$4_e?@m1>JZ8+f6Hi)?b7RnDz@C5hG&l+)KG%Dw~b+@iBl}&7anVf2PJx{s3WLy@B<T@*9T^w'
    'ToEx3S*N5W$X}p@Xx85vpQH9$eIrc{OLnjyT$D(ZjZDBOnh$Cf@EFHlINXgC+s~&byel>9&lpcw;GP&;(vufUu`RG{viWE{r6lbe'
    '9eC3^VRgEUY!|ih4-N&4mQA3(UoWQQe4sN#d)71r{^#nC@!>HiF}N8p&XL;Hon6AQeVLCk_GdamcW?sGo?MECm<_FSrr|q0x_RU<'
    '^D|!aC9vsW4{bU2{#j$^rg&5_?iz6%f`Qy!v-RlEK4>{hHm~0^mp&z^&=r7#HN#;?-dEt5ioBI~Tyw44Mi1s`=xU{7dK72x22Y$h'
    'Gd$maJ-eWBt2LD-o2D7T`q2hf5<5WPD3b8P{!6sXHLs~5h?9C3mr}dCnaD}BqeB74nNOFJDj8@hknj8V6Ye_f-*7D!z9wGKyh)ZP'
    'ZhFsVa4l;C<DIIH=J|8!=3Jxsky700$efv}P&-TzXck4&f-Y&$IYsr_s|v7hFJuGHi{m*s^ndv@So)Z4&z=a(%~wl$q;acfH1^O7'
    '64D+qOF~6~S8D|={w@>&9h$R8kC4!|BuxCcLWcSTc0ZIm`fEa$Y-Zdglr+{4gv<1HRCATo9mn2Szv65nhmX;&i&uo`nSsW3h88Z6'
    'RdndSM(qF^ZegtT<E&6bcvy#@z*_~917x_I?YDw>Gwu%JQzn!I6DK{1)#c`}Xo~vt0WlXtx*8LRGUNvgx0Z2+jL<|9^+ZN+oz4lV'
    'Fwh1kPJUHNWm%%3)5cF#+>lH2N&5Fn_>okog=(1@wd?~@XVp3$sQqlo2VZg$QO`=5S!Yp-hv=lK9BrXpULPdh!|8DYmVzIcZ51&H'
    'wG47XVP9I)L+PJifq5}1!E7zUvrjhp=!}tmWLK(=XMz83j5rK=-aipNc%+I8lR9wnM8~8yB5sY%g0I9l<N6X&Ewe%~QUFH|kc~cP'
    '5g&lxHEIgXY5)~o$5e}tyQxP)S@W9Z!AeAm6UzWrHg)`c9kr?i-(BmB<I@z!$M?eJLLwR@3}F2$oa7aB3MJ4y5|_TSsG_jGW-CYS'
    'HKwX)Z0-wh!c~3M?zT6cfKge(MxjclawjV@Nsl<W%mK~ZYb|PM2L2#6PmWukBsbVP&Kj>M8Cif+n1Ss$jkRP$zwz>s`lv`dC_ozJ'
    'f7;}-PkjC9C{m0y{DVE<PMUXKdS;L0hGnSIg}orI)tEf&Bh1OnWYT%h84Tvw%H&f(M{9f#_lw<EI7WOhnY1&tbZrpgug@ZNjD*<O'
    '1c#oE)xFP9pq@hPTt?ZF>3^hU_U(K}xzB!XV-j17tQVB;Y<bmsePbA7t*wxA76b%yn`h`$m8F}5#03k9OfKg67$o$nh;N-tBI}i`'
    '2B|gQn+=mxK_vtO5|hX)cL`N0N`Bn2i)e0oI<-{*5Y_d;IF64NVgTu=l(c(-EX6m9$dQ)w^_<Mg*ZcH?C<(p9ng}k9cA^5H3yR*o'
    'a|>)z`SQ9KT-MJt3NU*HXMj-#Hl&Ht6R{h9F5d#?iaV~|a-D4+#+^O3s?45M#W<|Y#<-A+&~zWQd9a^ea~Ksz7SoQ3VihjOvsu!m'
    'RKnmduR`zca=;%4^p(L{|LqmOQXrlD{O&OeX=b;Oy7aYvL<i9f4On*rY%zgKNMHUYsTNs%o@gn6xrHzcTb0Cy#m7o{wu~gjU1ruZ'
    'Rj1~~#&Her*U|{+!Da`3<$veQ?y0d4nmKUF!l%xY&?^N_RhdthrA0(zolOz(SHgZ(iaUz{221`4EV|McXS7_pV$p}f`%~?^pb#(7'
    '`Qqg<;GSEQg0ZsFIwckiC@3VF<Z8c?-o8gI(cReG*o)TY+;HlyazH`wlH24Wkr5*FJyW6Evth&CR#DGM+&BM;PXr7l`c7c3`+)aw'
    '^iJqx^ugj{XJ4RLc@j?;XLw&ve02jL*@DjmX4ZF8k~qyIkr+19CUZI;{-4Jp<)<~&)m~0sDABJynwbKWGR_qk|8!IXSb5G!6#HkL'
    'J^?#9D@cm))`;gz63fX{io!PMWqWnCS%UgJH15s-z&;wY5LHfPifEa=j+TUyRp`!MX`5Ul?sZKB)75H;JUz@uX;YC;zK*L|Bui>j'
    'b+`yq$kwG+pni1PF-59UqA36ha&7*z%!@vU953|*z57Q+Cj5gzgpVNZPf(67Jw>Yq;%QR$Z7$Z)H&V=Vx*WJ^XS^X&E3Zo3+m_GL'
    '4&FmCt|d0Bh3czKGht#|fI#!Ep6=t0c|UlXeVo*<qys)(z&AbW)c3KJ0(B1Omq#{tC^jt)AXI+ZD&CD#2#7s_?br$O2a!x0(_f8>'
    'n(?kXIbiKng0S{gRAK*IH+@72gE+f##{3`cI#-5p({elo5cAVC;8-TL4TR$k4N!yPE+6#J;mt*~u3c0Z$j3=jpBmMdg31|D^F_2{'
    'I~VhUt)%NbFtc)OVOB>*NVS1*hDyipcH%P02zP^R?D^_?>Q{6C%pMoS8Jt`3CfokRk-{?Jk3hA6DyJ#foDgO=4_XKg(b$i&Yf1H~'
    'S0!r?^6by3c8IUxvyA{pvKA?OALANfQF@Z{&H!axL*sXmJf*p>5i6lnU;fXIWcji(e(XmK+DJ3~oO*O(OF!1s7P8;Y!x9pSO~-Ah'
    'GvThfw`SBi4f*cYRT%A(q_H2Z#G?fH*qptGe*t;z>2Ha9cxkN2AoCDS3htTtZWK&dJHQLjf=8oGj6Rse0ondp(I;<3puxwM8EyWr'
    'SU3!uRAb{TGn`#;MF%}q?*C%VUw3Gg+_Jx;AJn$DrZ>h+K7%9^=u#FHmVs88uFAAbjz7D0qw!gl)IYA?kx~<!2Ecf?71S`QQr{?)'
    'BNFAlKwZJLV8fK6F@>w^wwR4&OmDPm%r=$9PXlJ3q=k92tpfF(@7mv(@L`wX?M{nJEK)o;&<Kb!6f38$vW2=Id0{Q_Nx+TeUK&0+'
    '6#U(rWE~CgWD{mXs?PPWpDdF?_tO|WnRNu*RJ?&6mmS{@zw+2q+G{{oHM2|D*v6jq{Tag2`dXFS7C<4zxOD@#Mo*V@_||F4TG$|*'
    'G=8mWNNrcNvNs#GPL3SKm~Wy^7h_P-(uw_<_d?ek=9v^2B-2DM58Iw8@<8sQIhENv1vMkOHQDe&L6T5F?K$NoEH)`_T$$Q-Xt&Sx'
    'Ch?YXx>6NRx3y2}+Vc5x$A`0cS6!WA!rVqo=seMh0DD5)1RVSXkeO7oZtlyykDm9gd%OVcVse<mOgX_uXV|?E)aN;;toeY)#K7g-'
    '4|woBb{%?=WH*|mrXEl(hAXNFbC>26s6As+mp(y}0CkDwqo6U>WC*S;Try~m?3jj!aPVSZCTRBDm|HMTBO|>X99nSGEX<19YxB>u'
    'qje5#xnFf>MJDc*Jt)#Q;qwzR*^RJoIfEypm%+6_1e8N;y9)$XP1tO1^K>!Z=EJQyx%jq@-9eABC_(lO)8|30v!FM%llpxwaB;(X'
    'UY2_hNs=-1uEM7h@-O5)l!ZAO>%Z(=2__r!bg^J|13%3?UFwv_I)%8X&?*eiP;{KAuE?qz1seR)*L@5EHcnx`r4gXq?NECLY^(P1'
    'lT^+NHEZuN|I&@DjKc6Rc$#L>mE2o-9>Do^WM81{5!SC$NWp@XU+)x8?%jTpxARpplS8$Bw99}f@Lm1dfRh0DSoQgGx?eJ@*jZ0K'
    'Nc4o6qR)UHpd}ChhH7Kx%nE+{9XzW%ih*=)d8PRE>Tl$U+v$r=%GNs$bEvkMMw^tiJxTC*Jn19H7P1l#rSR%vars$jGcL>-Q~>os'
    'v)#BSS;RVZlw68qep0o0+vWAzcFpkvM0@hd2Y`i3whviUqyWsn?QZilT?U)!MhHQye#{~%mIXbJy+o14I#bBXJ-D|trlw)N4W!F$'
    '0<*@F*u(+8v2xs}I5kTQTH$7D)E-^V#5A6RlTkyI6<0qw`fg9@1dyybi^Akl71@~){9Ye%1QXBTFX#Bd^Z#|&%B%ecy0vi)1v4}Q'
    'I+*v<u${q3!Xu8jvtW-@Xw(CL`!J_VI<~~Iyr?<HT%0r)9@L$ab;lqLTUs>);M24`5hNI~**Tc&zK~0(=0J~=k&&9A1rV&QnF}>+'
    '@VKr}&4vHYLp$a8T6zm{RF@w8E2>dkK}KeI=SAeWx=+lgf>#V2&W^ktyb2@kIAQ$ts3eh`Uy*bhVx{&`YPg{F@%=QeokN-3X{MnE'
    'HPw*<=QysG6+vN#$0-TGGkcdYad8OQYyeP{R@Ek(_}p~&I!fHypXK#@-f_Ixn5%Lr`&9I*(dnUZ+{X^XT}6R<23jG|B1JNMkmria'
    'GUJH3Qi>?|t4Zefue`ZIUG2_u2=`m@)Dqp3y2gWv63NQYME?L&w$ktQt;i_FPGg8ECN4)Oj&i8cK}28x+q$iTi^LnMk=E+E(ypP9'
    'yrRl`SI;55=o7j57XL3l(`X8jVa%{8Em=Cx|EPO;(kz32sTDyu*?bmA`u{{SnD)nT#oP;YZL@;wl8tYkG`<+B)<3-c{q}&7q84an'
    'TUyu=iX-;I&!0D2{0J1Z`5PatWB#B0xx>^Wexf2H=)9IS)lFK<=+-{=!kim@_Cbh?d1oBO$`4(jZ<TthQ<}E%vH`YQ2>+JoiS*(o'
    '+!(R^->k9phSy)X)Wp;n|7)|c)AuI@P4fua^RT0aX)f2gmecPE;Lp!E#o*QyX?!8@Fdj&H>vZx4SXZSgwhJLcJ?CDOokwuhD^veA'
    'rZa&_*sj{qUiuVS=Qn)fyJSdFLE1w)i4xzOoKj3%Qv}#^&Lf-kq{T>lCy>*kQwh9^aq*rvsK^?#Dlh2v#yG#yxvKBJin~7KZJ0ML'
    'pJJjYUBJ*jq>GI<oU|s2%N>=>%7bXp>iy5s!iys<R)cQpws&yizi*0UVLqnX96DS1hQt`b1<Y#X<M}G930A`!3l?06)O(Vegz_=?'
    'w3MC$7&E_5R7K@1T9}-uT7MaAf~H%*TCm7;(BdMjiYOn#1Y~tO7<t)8<=tlOPhRnL&QleI$@{P@yJzJ##`G6^ILH>h!;D?Ek`A>+'
    'F^tT8(IaTXv_1`m(80CQUY;JF&}lK33wltHYDTm*ZimM{-BSW;hZG@h(banMJ9)TL)SJjmlcLhGBO0u8%VqOp3wxQ+?<t@m+Fqt5'
    'mvS=7X6SnJJ>fvw`$Tb47KjVBwLlBysoG|+OG+1^e@FZW#AANWv3APiR0!{pxPh!QTAs3YwlIP|HLa9)W^Gr|zpw|E9Z;D&CDip^'
    'q+)GI23c?y+)SBkx(CTN7dyd!8tqih$#XaUN)BYU4%*~>)#^$d*2FXrV&n6ZptWC$<~nC5aks~!eAPJ&;&j^54@0FtU<%(e-X2co'
    'E9>M8T?sJL$TgN%t<^-tldXN9Igk_D8!l}y+v#_s@d<roi3t;-?tX3nV-YG`br-89w+7NV5_8nV?179MJJf+gpUy2V<-bt`IzNu+'
    'z4pTLHqO_cU%#TAMLR};m1!EZFKL3?=sVbu!wFyhZ5iqyR#5A%>g!)I7!#r0DhmM8hlP(8My?^DTUXWp1C}w<Wv+|ZmX1ON2LlGV'
    'Xo>Y6SdJC(AB;dh?0F^AD4}m%FHHt-u==@xH!NU<{H2HPd)^r#Mq>S$3o3~Jl$dRXU+j{`CaK^+MA;qF2O?0SMmhi`f#}Rh=p~A*'
    '1pu!Qd4TmgRCs|Zpa1k2QUL5`51Laqj{xIMBjBZQDQeX_24h3ST(=MJ8;M}qdaNZrM~?^p^U+>=%za{!AG>q<KQS++@k^qsM8C)v'
    'h8b$i6-R=PTSRtJno(X_tCX;+as0C0z#@1sIGNmB2yeZ<+xWk<0dpUPj3rWwbS~OoQX(|!51>HiLml_QvniR<2f-Olse6zpWzGyv'
    '{Zdj1H)F@C-f!=hldWiN@(|9Ht8>+~W46%gW*IxQ53cr5ZO%Kp$b3-A6NxtH32d-9*dmISMHm#hSe_}S&80vI%Orvk00KgmXLM3u'
    ';-v2pv7o`-L^Nko5PlS>CFivv-ps;wdvnCOHn>KgQGKgIn1P}*CC_E-ZwFk0a$8PGx3IE$8PNQ>s}QC}GZS)J{<-_FexmLi*&}+6'
    'Zv|zwCf0z<DUNY|mxO&Gm4Je}-j9C}FT`)5$KRo}+gfI&E<QjuEy`p1V{Os^11QjDkSz6Q{U}cFWPJqoJ)(c3j_qEb;edOT@7U>`'
    'r4I}xsJ_i#;O~}AgA}WgJdf1teYA`SeI`!zJas<zU;vS^)`9nTY^yJTbqOq)L$*d*yi|pdkZ#!^Vzh2XFWrR<U?q({zr(qln=ZH+'
    ')huMIVaD6pVaMpZq!)$V_DO_uh-kNWW$IjmVB7m(+HK04TsoYh391;qMfV~{PI8$u=f!ZaZL3xW#aDgKO)HmB0#;;qUb#u4UtasV'
    '{cz&jYp~Paf`x$xXFbI(R39h&wyMLHaVVku5CdQbKA|?V6${oCrQ&NStlHA7QS|19Gh!Mn1vdY=*FN=d>vzRIS;aVXh|S8E7$NQq'
    'gd->7;|4b7nV#LEATskw8cDrwOvqXpWi!A--)hU*vyQElO5qWw#l8$TvP_&ogM<e`Tzv9t9<jzyQ=)fsWSCtjhm?s=3{o|lEV6Cw'
    '*S>B99mHEm!Ax?@0k@lr$a9pl;G9Cr)MmmU4*YF=h6+ft`6YyYZ>I_t=de}uloa+=*EW{3NIfvbvdwr&#SQEhjhss7y<9*6zTS)_'
    '0E142yuQMLYcLYPJYIi^9)*C!`Y-6aIdAWtRJQclUv5h`WoU%Qb%4tsMYv5O2r#y`kHI~oWHx`;(hqihUZ`5qO`*p=?WcnFT<Y0D'
    '<<mMCWMEqn4jRpSL~<Gk0868Ql+dxS$7gkMt1yRA3wi4FLxO)yxuc~6$oMj}a<#Lw&yeqOS<4n<O)K|~W1OXf?mn$1vj38dWGa(c'
    'FkUa^!;<SIvpR>*+uIm1>qA03s$#6COY`THXioAh=00@>?9pPI05fx{xP{=R^#ur4G#xh%3d_Wu6g=iy5KzLrh#p)7(S>c+hCG*}'
    '8zp@HcLhhJkzw>sLi}2V-XmgJxABaR5VWOdCdq?&%71=RLzyS@##^4^*C2D@l^I8Ve3Rc#eCe`w&ktV%oAi*TSvrUGSF~z3r5S{%'
    'Su*{)nzCVGkaHN_%Gy<F<d#GEFKJ)Z{GK=L<}zKWG&6%ZCa>p!*H#c>GIL67$JRoRa)F&0(mgkS>g8Qyl#MZFl!q~2YR~r$2=Ma|'
    'HltAeK%{aCZMb|4VVR!SFcOi~6y%UUo<x1!?9^U*(j3Bft;dg0P5x}7T5j3b-;o3tQ&yTSn(^_=NG&(4F>jM$6-EQEO<p=jhCK01'
    'b}qDvLZz2}+~Ah09TNUmV{mAPJlkw=sYCP`?P#U6{Mb-c1?&!=x<a@s>!vH#2zDz_``Xk|D=t^j$U|nPeDQUVk<7+jZ^Hc%>khMd'
    'k9hRkRQ|K~l&IXPD+ReZJBR`GGWM-ged$%CgyI&9((JI=yh^nD%~44LaCnI0#<7u%_=U<r*-;R?`j~DhImZc!OBrX@sO;n<14*b6'
    'yrk{t)TCKR`eiw#wlIoAbt4mNWn~{9Vp?U|kG9Kb?T?Pa-pOOS-O)DuzzTI5;1o%id|vnvrt0FPI#i#e$P2cey+6XgVe0ld9c#OR'
    '%Ra+W9_9?rjV(!%4<3@rOa7yi%Ih{@8izt`w@0$FfkPS+EIJOH5?C5?MpzGnu}-4HTq{5U4U1#17Vc*~dwd2FqW{pPcTQU)5Cx^T'
    'JKhuO`gaVm#3Ait`UxkhSU+N(di2eVA2;S?t^BE-wo~w<(cXZO(O-Z3aiDWNySyJKj6B1wZF#`e9Zy`-&VjR)z>b;fG2S<md|QAt'
    '3$m7c97#b?Ter+eJgJBJX(Z4w^qnzu%ZM5`zhO?$gIGPF$7q?CM?zrgJyy{-ZtYW=Gc+=^>S(Dlk%!@>ypD>FUugYt{OpCg0uE=e'
    '#2Oj9t9$%@gD(~hgVzpczzSxns0lyuM0M0a$X@?xAv@smr6lo%gjBwn3Mw^ES5sN;)#ewR@SA~gKOMnqfeDjJnX%F=HMw4k&wIpE'
    'D-D=b6V42L890LlAG<S@Q;;j24>i!_sFCN^9SArIK%{|a!!{94GR&T%#L?xN#EID=$^mwnrcA}ZsjwVp8|^&~!_6oCH$rMMK`W`|'
    '`nXg{G0SG8F4ylNFGVE(KWnW3_1-d++BEVc^_Xojn1?NkcnJ>2D2b306l5$KG7ccxfc6j&%oi|^#VhT}kMaz<D!7{D`&jk|90cBz'
    'hWv3u4BjsbyVoOu?KiXfl`8K^9J`{WF?2JmMeS96gOaVqJ;{Jp$zvkcffZHUniv!_Lt-)i3nFjQvCg-c@1=Vg&Gox%Y);iG?F92='
    'oF#JJIe3NIg`ave|Lnn%@+g~)vG#ISo_OBI#}6?Yd1(OV1v4$@QARXtp;6Tlk?*I)OONHSU>gmBBhH=U5KEH0+0`Q}Dygh8{U<A?'
    '`@_k1d3I2Lhwx~uY(~cLXtC*4Qcu!I^ThE>L=y@AI>KjamYobN3U2iBD=wG9+~R(mtY4@Wa1cBsUOW}y!|lt`kQM7_n~*_GeIu9('
    'V^DFe7T!C2b?(1y^y;zCA`YY&^c1s+C=<8!%4*tlVTQqB`;s_jTU2O)!Rgb@_4rajZKt>B{&g5D#)2*sXKR_D83A1_fUDqmAIEbP'
    'uIKG9m%|BBqP?t>m+tB2ds}xFtjo(_g=&5e76VZU?xO8u#O>*^HM~ASUOn+QwU7h*vPd9gg^eYWqygbAyM$(2X_c0br;D<nwl)x7'
    '_qjl)rbR(Db$$ZGMpmzv{4m|GS}Y|TiUw1>IQn)DSFdGqbaF+(UN^kHwvbmaMs+Y`tuylHh)oP7nls~*DVfVrXnL+D^Jp%U_dE)v'
    'ZXMf30)znZroNw4Hk|1soq+>XMdSXdJw-OShaXkYW&}jfChe*<Q@(aWry8RzRtA<KG*jgFcSC<W_|pU_&M_bx*U{F7v9n4q^8%u$'
    'J-LDZB$0jDz-53N>es#|0?oLT%s7nZN(8Z{lxpvSY5?Z{eY}aZ>|i9du#0SJ1sqsVxjB*rrz@)<EnHZ5fa2Bl>5TH{3xOlb=j?W5'
    'iBGnj^b(86)PyGmvF}Fe_H@)@sDdu@=T{x^EvdJ(U!xAodUiKnqQv#<ij^}P7A_|<4klQ;-Bf#BSVl@45w@`wg$!uM0<V#lT+d?R'
    'A*L18$ELsSAXp^_MCUAVqf!$>2daSo3zZ~1XMl2<<G}<$K1!^f41<fN&3MpARw?5e#{MTOv;2biKroPoCJVhT6|CE^?W)Arw?Pqj'
    'T)7d<xJX4>-Xf`iim*N2bgi8j)ycL=O%Y(50Y%)3vP4d5YoTXv0FR7PGAdwN@qR&YB$4}84Cm8yQar(77evjPYhW|2Zcl_KP954M'
    'C52<9*6Mu*Ne+W_SN;?mOsB{=O0f_bS&+$9K^V}x@#tkwb$i;d1sgEeBL~Qg6(ch=#l?5!&aWykb<Et^16W3x-*>lyX+hn<i@PSJ'
    '$c=6mZRIN?M+hB|O4xAcDaO_`+zLx1c-i<~<W7ME%!t-jp}8OIs%MXJd{Eh-RD=JB2xBeqrAF!Ah7x2DWT3;pQm51?nfv%3VJOu='
    'GAf=#YI)?t+iXhxE8W9ITVlPCf&+}{?)y!4JzLXE6*inIZ(+>Q+O<_hG0&jQVczySbXLznO822^AsP%)+NkDtkI5aL6wC;r>F8vn'
    'W?PLkksI{xZCCR`)F=Pbq-1nm78W_Ym*eN{4BTL=vo|Il9Mp0DhgREr0ysbNtI~e@Y`Gc4gV^Wta-3v1>;UBMNc8pa!m|e2G%9BH'
    'g$x+nlI05XzCO&cnWfm-ggUVWFMeDFGb*6^7v@=Vr&R747;s<001LugX0Y*+34gzji&D-S#z07??PK=8<vE$8kAT_3t|*i()>V%J'
    'QS>-6S&;|jZnQ-f_+2#6Fld?YMz0tpXNxam9`hJxWfD!xbkJ;9_M<@2KbT(Jxu@dZ{u>iL6k=xxCk*9db8>N3U-=FRVmEDN7z8v-'
    'eFTFMK;RDT(Mec;PeSP9an%IqHq@W!q#wLM#8+EGafGCBNkiNsykb+_Zo}+rn4h&rmf8VJn5fktT6SP=(NKchi$EEv5D>X4mpRr='
    'z^c{o6u=A}=Q&q;8ypCcI!aI&pn25xq?Dx}S9^}W%n7b}_3p^^v(7R1ZwT;)B&6;jhF263EjSlH{obla1gp*bK~=#{>FoKuo?T8&'
    'sC|yC1sCQKO+8lILDeINm=7}2lR|&{uck77e(uvy_PK0<E<-efnXs1ztVRvK%i7xj?`=*%eWy=WsTDC9PBb1VQK18ng^)&lBTsaE'
    'ACHsgM#oqVgbKxw&(<(F2EdSqT-cTXd5liMzBSk!-${fcW^b=zv*olrPWg-LDxrDmw`2QX9k&({&mrV#wH_%7Q^EKbqduI_!Hd#5'
    'ARfkxs(3NpnZgffw#FoJlEq~}PW4=!V(G6$;11h$FT{6!N+$2iC*R$A-X+IG9=pxUn4zaj+d{3IVfK(1fF$gmcj}-9Yr<QXW9<>;'
    '%T3gp-JZ=ga7c-*$A|~;WtDEkvIw)<|Lcs`1-tW7>H1n3+{DEKfV&>Vkb~M+ml>KlqDjo8l?)W`^N{TV3YU|B^R&Vt6DskrwDr|@'
    'T<<O1-Ier$cyvO^E8hrg%wEiMQV%sBTG)On5YmR92MFI||JON15jMy!`XD@$T;Z@ImYLZwmtYX~V@_kL@{Jxl;z;}^1P%e~1a9o~'
    'l?lZgCD%+dQ?FaOA~4Qwcm`7t=X4qR5}mGIhamQLl41y;+yfOzln#MN5WvA(9APOFY?QxsrZkql1T%~iLq10X-{A0nHs-hX;9+XH'
    'rvVqG?;bH!F1<*lL7VIGfU|83R5$?ixkB`=k=iz8I2^ec=qd9Ng#iknN9s0`Zt@aoCT}PZA2jYeQRCe1d_7$?Z&cOh=v;3%G8Oi*'
    'm@j>N8X^S_!8IMQb*;PSbE+l`gbI@bJygUeM<qbqBT~FG`v_P1L%j4sUkEYJRZ-KrH9&y)N&m+fE2NWP)}!)sx0cvHr}j+0tEvmk'
    '*dTT6MF^;UTpD_atGw%c1||1H@C#bZMa{&^#cY|)PcQ6{gHZ*pk0g_H>YQw;_3eM5_i6Vb?6TRT4>*z<E3|KBL*SRLIMk_oSr%n?'
    '->?3}(0*s-C@J{+w7UiT;;uk~TB>Y{O(wfn@@w9}$u)jJo*Y+;b;+iqR{G|B_>1*>{fV#4Iu|=Cd?#x@B-7SVC7BAF+}4~@)$z1x'
    '_`u{NDM7zkqj;_%znqmX%1KLFurVO3f)nj&<WZUlAwxDI%{W=lB7Eu$pH>EE3+Ky!gl{aT$rU|V%e|<{{kNYPig_2$tDheiy8(GI'
    '=|{mh?x(a<`ADk9wCeOh2k)yru<mFgKvfwYf)(g;bEi$h9Lx54TR2MM*amW)?ykU)_?oLC$_bDroYNgJN!z$OzwZt})4G>@2ZEXU'
    '3K+zv914N+6}mVqti4vPMa3u_xGcbQ%R8ivpN+v6YNve;QoN^|p*5GMC}9j*aJF~f^*#twOo<KJ3ooZ4#|(;Q3l+O0Imjd>RK$o<'
    'mC!(t7jCrT;9G9~P}!5&eI3>1M)S!C7yN9g@3d>4HA{H3{A>@HB(SN($lMhYFIzvgoK!CVh=t_udA`TezSLpO&USR=0PrzqV>yrA'
    '!7h^g_9aMr+tW^jG7Isz!a%J=<z&+cJ?V=Q)5|bwBHJ;xn`kzdx#AzMB@IeiaEVbgYo*ohh@3t{Gr39@U478-Pvn~iHW%4>9lKg2'
    'WvYVgAZhb(c!*`|2u#_zhiNaK!=ioCI-`B6DCNGQ1iBe97@29xL(Ma5gChX<#et&2Q0Pn{1<Yaa&Scchn@e%tBl{{^JV~-2f)Ul7'
    'vDY9a+Wllr>~ldfgT7iU0utWex<0Sq<FI>MxmBu`+PhSpedNi!Mlt^)$ShaeMr?Fs|56q9xDnehCpV0Zh|+Zf&V9c4BEn|uY`h$w'
    '`lvlx1Ztm})j@3=)y9{3LwQZ&i_KmvSWL+_L>R~+4d^U;>UF6(D1X5IAO^K>#bKKyeXTveDlIU08w?2N=B|`N%zmw-xlF;(<Iv)M'
    '%M-p<n>!pqwnfN%@RmSBt}ZOt#s63WZ8Gr~#o+to|2sJG0<u3TI|KDcFjEHPyUZGd9$0^(@Pc!eF+G0)ry_ND<q&$86w)#kn3v@D'
    ')3ji5OWZ<Tu?hv)_{%f{IN%&CS=V_rjjeS9|1Sbn!_3GJT-=T+jNv{4u-YNo76@7z4Ax}YX+7DQVz~Dqw-9wJHxh=;gW=*w@A4Jr'
    ')k_Y1uLsRcMWN_ED5hJQJmcK|)T;g<#%F(LXh>I3jLIEN1~^DEoS)s4%78C11SNZMA4@n+B+uI0{K5mDvwH*<x_=b$&+f4~a6kjp'
    'c$UJ^M*wE5^~DPeq2hkvu~%3o)Kk-Y4U-D<eudj_{*pQFRje)iGOq?3sI{?7o^D>e_GQ2ZkFF=eMhGqFtJ7H9y_N192O8SU$#JfW'
    '5_LT?C<t7%-Ec!wdBD8!X^ynkKN<1ciQEcfo=Gx>Nxd4xq9Y3QeHu<8E7E+KuO(sPJ6mNk{NYEwKr3R3NU=z2vWXdhv{?P!*w2FM'
    '3M6>{ExCS&V1`3MBJ@w$g;Z7ZRxHW2kAFMNZ`ez<2C5F5#He)U-GPBSYMe0+=P-Wu%3X~0H2muri#s>J^r+(@JY~pM^3EZbca&7%'
    '10JWwep}wns<A-Q6x6X7<Cg<~R~(kkqPa<M=A#Y0sH&m}ME)#Dg4y;8%QnF|R9qZLq-QC9KS_R<IyHIKID2?bl^HsLcN(qX(LVw('
    '5Fy;w!QzoNh#6;HnB;EYpBcZQ(g&w^=>DY0yefwEA|+g>i$_knMRpUCNhT;qt3N{AM+_v+jP8G)deE^^bCqrW?#a~dF`{O05R-4R'
    '#N*#mVDtOwDCe)w(1IjCW@+JbJ8fB(l`NF|er1fDR6ZxU2t&cOSe8N~`9~R>c`>+ycKEUWC3O*_t--`6Go%|MvDgk-!joZDAuBa1'
    'nNev5{*-wc&0Bq<9CizTN}xs#gB$IWa&E|$rLRfDwn07;ueC;8Do>@4J&Ol<p798GZ&1dDE-Fs%L5l!Cc?hLg|I7rkaGDPq7LgR>'
    'Wk(Wq(YW32E?;1N@p6$e=4Q(BRnf4@XmTssYVL=&cyE+~Pj1U-xrTSc5t=if!j79COZsPIJya|$r<Kh>IzsNGS<(5aF-zJ@<`tcM'
    'G2!TtwT1i@T)i;Jo|}I>NRswX=Z(RdCCb7!jAUk>$ws1SgR?r3!B62FD-ZD*)l;EnN;e>8gIkUlPMm|jnRoQ7a+x#4?{$#2fepuq'
    'W}56S&l@o)u1oN9YGq0X=>Ce|zjh`)fH74pOlyv@x)g^bwxr*Vdbe+{bmU3j!FeGE8KHgXVj|;YXZ@BK%<lP<iGNt2oqur6&1tz7'
    'x(gw=xTQ-`&2~>h?vXso(T4q2Muwz%11HL|AGkE@cEe5Qrxjl6GE=Y5o5#|pxiC<Ga(`YP#VPdB>9*k`bu~hSeTBt;<V=L^k5dtm'
    'VZZ2#)=gv#blqfgH_+w$He1BtGl{s^FMZ?nsdf92bT--~p3Jy?`p-{^n<erzm%$a%P@9xQ^n-!o72*L$W!4z!qGo$#4mV8R$2dsJ'
    '+ZM<8xj@5={{r={Q8<azGGTQWBSpS>1<PFe40A$eLn0>M$4$IBD~$e`a>_Zr(hoM{Ta4_t+_?s!O43T4vZdqIAaqGvCSV=Ketz@^'
    '&wR5ypa1R=8UXBbQ>XUUM)YP?U0cGFW$)-=WofbZVH^jtKHJX*nB$C7r3YF@FIQcZ{sO~m$-k<mfR=#BC~_Vh_|I!w!Vq6TkKSP@'
    'hK<<bsk@S(3&Md}(hThxuF_#rt;abKgFU@7mhl|XV9N6W#|({ncq`6<gG3XBtkpkM1acET?LD{Mrrzl!78y7v?7h+Fgz5vF#~>!F'
    '0-S=jcEF{~L?)uy%6=q}^FPTl7CR6%ypBgZWDz5!;Y;^7VHEWV%dI6#X%zdDQEwE~3y#Z>Pzy?}QkyWOmYToYhlO3+>LJ?wYv}Sj'
    '&{v|9nF+(~(I71-@fbrpKlyzDHg^|(5n%*>V~T6_#RgC%LJdC~a!PG<x#eFDjC0doxXdkwMc-`AKp30hdR4`?pTYH=9?o@)hXH)L'
    'Y9K6pv(4!%1(fx#@0j5&KW56@DO3ItxxV`Muyo3=xk6EYLdZYa?;NaKd%_=yzLtIJ@X)a%=V&P2n3)w4iCQgp6xp%@s$^$YHLjO%'
    'Avcsvbgq@7PvqYO^5_@Yv>MIOOrc<53#-t!8(NYJQ!pCbkfCgYYN$>}9DZ)q*u+eH@ao>mEqb7QI+oadelqwPzY^ta2pmDqFn7#r'
    'q5qz5_L(6TETBE-&=@C<Mt5JQ>FK#11RyrU_0Gh`Q`{koIzYOn_dW0gcXt}MOrDZVIPoW!k#V24j6|B7+iSL3ePq<}3>F32H{&qz'
    'o{Y4E#VHgLa6XE(9hezVr~nmv{H`FOSqaaw!LXol)6W6kgLpKcfEgWmvom@aG{#pP#`y9^q<u1#UQuySJV<;<ziH;j0kb%F!}{DZ'
    'r87RjJk4=0KT#xhS%T|(IMEFW16ybE)z$XC<P7Ygu4C}kRtyrBXL%8Ma%Yft>!EoT>x&6`5%KlF&FAfU*(3ybs4XgEgc4Vjje)^D'
    '#icpC!ma`#?8xa4r!B(hciQyyw9gx_zi+Lt%;^wln-@5A;3EN4`Q22#{f(j<K+@O&^X;Xs(bct-B;fKteAsH-somko_~GkD%+jvG'
    '*`h7xE&=-TYGeY@CyZ$6&3jNr>LOioSmP<-yI>*7&E(xAU6NHP=-9}>uk}^nEK}1jgO9_YItCT)l2wdI?mMx??4@r(dp>v}h44r!'
    'pMha*gFmjHwNr`FX?&~sOA7#<)#a|LQpG15u<RKowKIB)(wQ6{0*4a^t*Np`SR>4j+8nu0&5qYL{|2vZsKOts7twC4Hlc3cl(PPB'
    'jrxg2h`#V5C8=SuZ@wxFLdP^@PziF)I5KjcXpkd;xVj<{q73j|gJ`FMfN^xMxEs0FOmc!!fw1+E!TzW@`S>838k?cl<!hYhUT=3*'
    'e%lIF;UshxlokDRPGyb~xC2so=rkc(Yr}R%wO;idVbwdEKkcz{05DVFAm}+?zI)jGE(gi*$4hKpeyPyN?!9CCr9%aeW~=X4&o5+r'
    'Cl?&M2KO1Dqg&skUIa)MM#Y8&fTTqL%%QPHzBzJztkAurl{j-C8*kJSLC?JaRY!ww0sdXUi>9<UV_xkYe48Z5#tWWbzhE?#!1|C3'
    '=21dlzoM&J6&EI;yx`7a1SFA<BzRm2$m=JBZ7f4{^<E0LYkX0sLgiIw3Oq_ON<SQlTgJA46tJhs35e=7HnuGOv`J~OyZwq&lrWL?'
    '870%y1u-7zFDjY9;CR3$XDpZlx_5?fE7N+lxVY{a6KoXhurSHnKwpfrkIy4KU1X<&zrOy4hMopPzows$b3rz^jyK#i*E`^lK=U`t'
    'bByron1CmGyS5y0EvoQo_T5Xl%|p#j)>8+FU<yw$$zr-ghHvvVNVZSo@9nv(QTSJI7Y;dY#q1zi{Ie1(%E5CVer>}@^W7*gDkKOL'
    'SCNmCN@2|~`^4$xln>a+zU7PlP}PZmaEfe9>l*w>hOHC9omrgfE+K3Xq@t-=R~1v(_y_Zmn38o~s<6{8beT*VMAX4gv-AoaT3Lg4'
    'yxmi()Zl;>fS%fq^<4snwmaKXnA)oB*kr)k*O<(h84|-5#&GK?5h?-!;Ray4$Bd!FCP+G|YbUx10M29ioqzpA7{@!?l$vKfS9jlR'
    '=q`ySdb?P`F4dZCu^s9R8_@ly%3n~Gi4(#mO(qA;HG?{D4z5ya%ij8gC9JAa?b~#GdzgAL9zNmVzj0e=ik$;)9++gfYK8w9my+oT'
    'TfbS%UMCj`&C({ex8Q;oOM9oBgdhkD1qGzrP;5raksKXXPcj-_<K>whHZm!iK^Obx%jD0pY_8<EH!rtohDI8vg4D~uWuIgy^m(aK'
    '<xoKPYpEClHHU5;{MsaR?{Gq%vn{vGnWWVpk01akal2=y(j3z+P)ka!*UQFnQu!{(EDn#Zk3P8><=?INY557Ibxr&gIwFZ)BCl%x'
    '7Q<sKcvW3qKtNCy^t=BL$aobWI?)@B(Y)0qK!v;O=~=_aP`N0rHwtAjiTws<X+!JhvJqREJ?Q!umw*D*w$v!y+H*ZMx4`z6_c-1G'
    '8>N%Rm7YlZOQ<VIB#L}yU90qJ$y%a&-RKEI=lTK~B&jcgVvXm*O}GA~nQ_S*enY$iJ+i8AkD&lZ96fc<%MNo-MOCU?6nJUbtX&r*'
    'LPi{YR%p{BeM(J-((VR6w4VsNUzHCZsn}=f=dKP@z67U>>DlQ{EACIqN@t@k#V>(j;qjd?3S_eq0V!w|ZT5C3D64a|zfj^0d*evF'
    'P1~z5unY5*+k!_}VZ>A_au+*v^8}U0;*O^BRv*e6aCPH7f++s;(@%iNXC=4^0V)5U4EX;zhXikQ!_MJ-$fRx)@6@fKHM}iA4yPl2'
    'SlhA>w1{WZ3tSA|=zF~M$<?n7y9luAGV`~OBPNQ@d$N2oL57^xB%V@AoK9<tfxRFU&bjREefoR4<)UMj4QN$X?L0vVr>yC(Nq%Kv'
    'URTxebM+G*`+wPh+u-q2!8F!a>}}_`<LQ**Di+II8Q$r7((Q_?mlM5ZG)TOWx__PJW_kO4pqkN%^PX0bQM}6P>;DzY+0fyvO>JO1'
    'bFn$$SQMY6C1%SW+g>AH@W*g1|F1oQp3mfnXxs6-(c(FrhRM(yKI~zz3;=Wa9?1(*^*rByudFw3*wB^d6*-bCSfE=F>ilZJYjFR6'
    'rb|4K=1!O=(_w3A6{58Cx$E}nxV!s0uOlcB{I9R;RR+_(rr^<b99?ggJ$3MViS$H!$7Z~1Id%>EbQ)h)mG)Vp{7^CE&i6AWU&u+b'
    '6fgo??WOg^qx4rdubmM*r1$2_d}Ffaa)YLce6Lw4S7YO%p28AV6fjg`gkl;Rk~DA3z}#a4EI}5i{szb8+spFoqod4wCoa%GrW_9`'
    '4B_7&lM)j?tQl2&{gNTR>tPdGJ|BRrlhg$-Y@*j{C7b?rUt2%6Hm5tp48V$BQzlFirCG4=kv2Wp{xfNHb&U058eVn(He(F*y5nLP'
    'i#^lFcb9QS<wbsBBMM$K#OW3n_4*C<ZoagLRnHSC7t$OLklYM_#3T!fmu-$do@Pk&eMX0*)<PP+<Snpi)2KKW|2K)K9a=c+X+$&H'
    '`9($NMNJan&lAI;rU?a%Db9YOt8S&?u+S?nF<$2^#Y)P9l%h1|)0%n`Tp-LPo+c5D0o{^Wq44Cle(As3wO<}(;tDV9->W$f&z{3`'
    'S8wwf=g>PQJBEyM)qQ2O0TbN>sm<r@)a}J$CILUZHEc{IVkpO>#=-L|y=-=WmVmMfpw?41>D#(z6JwY)4op_t0|x~y!(JEn@kAH7'
    'A(z>13$#|sEN31^c3X5Qv*q@W1L4pec9ayDyRv@TO9KE?;R3i^m7OjA+{Izi?j-eU?cr?f{Is(u|B0HAgh%Q+)<)s{zgRbsYxJT!'
    'Pu>Zfw?{Ld)fTg$-orZpLb=9MD$US|2FKQuUIdU1{w}YNeSwX2&e|U0R8IWa8A1cxK>)R-Y<TXK_YZuKKZ@+=dzE83`$Y=ab+HMg'
    'S7|w%O743*$deG|^vK=1p(udN53vm`jmV!UAw0}7o}l);fgjq=>RMXia_{zN{<hy}wNTB80?#5mxW&E_)kMEMjOFAK<F0Kd8Z$<c'
    'Xjs02bZ>!0EMo5Dhw#N2+o>*mMOLY3mJVDBIhFw?s|tEncR+1`yzCfg=Ib0cH83oz?l?qAvEfu8a_IWo{U$O|X4NHFr%+KcnQ2)w'
    'FRS>AoX;B59)rXeG?tc!EG+@)jvvoa8iHiL?0spDAyX3s!0_!Ax0!=`dQBO<0@XL0MtIVB=dXx-YhTZ82#XExRw@w*U$q8#_i6A?'
    '_Mc)%`!4or!OX#_n}<FQ98wAib<i$UJSCq~rrkj<cT0Vqq#(QGS}%M+8UGsxpg7KTE5tL+mhR$r#h-BFJI!Exu^8&hYUOtnUB2}N'
    'cBk5P5kIJdFT)!UgvY1<ZN!uE+b7#7&`&=k_^YcDViAA$u0{MXgK`)_WzlHUW=+dmud86ui(b}Fx+aq6S^Bj~;GJKC^Pn@mp|AH7'
    'x;ZVXerxpE7Ote)H52(5)&ksYTW7R&5sMPh5r|+mIbeE-HYnb{vBSaGX$G(_kf%o}+ZbmOokC{~qF~ollC_`UL_(d=-vJjf790Is'
    's&TPX**|LJ|9^tF?mN%Y$?H}84N{MnXfhKeUxJ;E$b8#N_Zfp7Yf~8bDU2AJ)|*@403Y`ZZiChL)Bfs(tXN$Ng@lu<J|9Vh=AZqw'
    'JL0NX09@X(6?F~7gz^yUUEx7ech{E(54l>cnW*9>XTa!E`O5BK%8s{z*t^T=d@uc;+PXre`0kiG*uhi8?GHJzI-ue)Zl5iW;bi*U'
    'HWs8bWA5j|%*}GEuwQN0sRe<lD0rg#JNQ{&FN+J^%wFxELQTzGym+1ev0ooMkpB%@H8j)e1N+pA26+F^1qAW=f@d<yhvBmHHQf;e'
    'nIwC=+%m}8jukPnWF7=d(kY6GA;f=7QNr!~16#6|Zr)hsqe}sY+&mKU&SXml7!UGLf6snew<R^fCYSG5ZL-cM>}ew6;CwZ^Ub3+6'
    '7tT9+YcZHw6-mtItNDeW!x5jSxa!zt5;aIa?$4=8x0)6m)b6<|bR5y6#Rr<-g_pB(k|X~)a*YOu|I?f=dYw-Qd}v%Dad!R;y1E9*'
    '4i=(&9@eY4ZGL>0f`O9kW88|FA)E?9*#eYMk3~HOFr-Ehz?(ww1ZWYv!v!qu975hs7@7EYkG>T2Ez^k0=XR@3gmI~6++?a;t+OoW'
    ';<%q0Cs3AfS^qacu3B82jyD02<njN^L-Xxtgzbf}^X?J)@f0=d_Vj&VFhX~vb(bUB(_^F}xhUh#bFM+72?~D%Ng<G{03xg$w2(UX'
    'e_hNH{x(wfoS*@c<x#4lE~GmwE5(NyPk%Wm>05}AnBJ`Ci?kAw;Larx^{c<x-;!l-M78P-$UfID<8T!~CCRSOP+S$o)IFT?I+W2|'
    'WPGVt{inl(8gG5}zr%X&G{aMdXFGPpaMgy<7Rv8apia?c_K1&W$GnZtmQ^4ZC^XvWKix#Q)p=Shm9$5H2IND%QrxcjgH)ddHGR|i'
    'p$O1E&01s}1QE8ukHXJSI+x|lzKWU1UBTllgJuh{=naW*5c8);LB9^Ds?i`jCeE>2=;N)QZD_VnM82lp*d2|)iqjL5qM5vh6$TZ$'
    'Zn<0+E{*P-I(1{@vCku$ULe_!&_#3Gn#w^c*J&H5%29H<QEG<=;=)m)uZpCx#e=qn9=DDO_)B5cKn9A`55)57pZ^IIZ~*UFu>DJ~'
    'J#}A~u!rkvQedVhAB?dN5?5_@f!DLa>8e{r9TrS*LA9p5m-li%I9A6Lmu$Z3Hl4U4up1JZOI@e%AY)ATZ=jRA7Qnq&3*bKBhw6T*'
    'Sy(geRSK%G+rW#EYL_GMUboT7;`Z@4>j95}T@H1s(nl;pKEK&cOs%W4L%!}+M2(Yk*Q$+abc`G<Fo1yVgYSNDTi%2#;fiq$#2tb2'
    ')Z*V~t}kaICYlEohA>3z(6(EPyLCAZ(1_pcJ72XS#+?U9j_5*r@UBQT0(QN2iY{yskAd=o^mu<0+^%U7@qVz4L9OV(;m8*f@@!v8'
    'c<agr^%srU-i@GZX_2a@sI*m>Iwk&6|IR4;^BY{G^WU;W*!ZF55PV;|jb#aduBD;G#Xm%Gi|JSfRmBv(DU6^C82T`dTbc_yh&@t4'
    'SLm1f52Ega`j}_El_mBqxM^}lrDouVkx(Tvs<_IZCl)`+)O|qR)cb9Jt(?3DwC1f$C$+Df5|QkzK>-nJmbBT5j0KM*vw=|9%>xBF'
    'bTxoOJ!;Ifpw|;(nP!u)*hF<Zo(_eJ@i~&Pg>D#9ksRt_Un0f+h;gmol#8X3)3k-Xz*>&(lTf+LN^SKIzivoNX;jrt*M@1_ai$U$'
    'keI-y?Oy6bM7jHWuo!=40<!ogh|{fYO*Cpi3@drTr_Ajg$aD5uGq4yl+n81L#h3PwC2(V8o>*~bk<N-xl|a_8qd+hw9U0{w-$1)C'
    '@_^NdR;qamn?6r9xfWvnoIY7Z+tUptW22&oKva|P1m4_(Hq{A=^?qn$x1h%Q%qntU{_gt@sX8Lv_t?BUw{><_42v21{96l22bKDk'
    'xm6+k*Sp`v&-UPKjQshhJ%iNFF~#IG0~?QeiCLFN3dzPJtaQy$I3jX5A&n_E*kj>L@o?0zF<OZ{O?8c<Xrd>e_NFRJf%GMiRUD3W'
    '0K;o01w2600`K+qR~FnaIg2$5OTY7f3dx9bAG|kFpq1)rW~((Rw%$*EAKbND^3h&@)xNX{R0WGf2lk!T@3AmJ@dn;4e*<Gbwh7y^'
    '6KnCv@a>yPccenCQrSq0XJ7B$nx|cUle~yWOp2uy4I7wrRIdmB;>H26juz`K9fiBpxfq^0B5ThR<xbm&>nVCvw#+!sX5PVr=Yqqz'
    'ZUcszY#H}?r;epo{OW*s2q+X!(PIazX?AxK1IbcMW<q(h8VLBe*x-9SnDzO*jvVuqEr%NT$WnwmfYHcW@F$i=VuByglE4d(%Y<fN'
    '#MY{7*Ya{r(a_rc6y7#7XJPKD=d>?5!q?f)4~vl#H>Z;VAD)d95MM@cR_DTY#}pBAw!zw%6|#Cqi$fgj<m@Id{_I_j$i!ymKbq!|'
    'nRfm1P<zG6EN{auB^o#1jCiMT*E5gAiBU~v*H#0+^n5RW>mKSm{HUIo5byz`_!c1P)L#1%0%sZO1}D>&$ZCMLvUk(_k-qkm+;bcG'
    '+XmiO`ObJi;iT#)Q=YHfEfE?__s$ZRMbc}JB_!3FqU&JEe^vc!{m^+VA~#S}=^G{}sQ&L1-B;&;a2qyaQ2on^B@{K>xubifya#f8'
    'ZssHOA~5BIcP4s3NYYb@wy0js8cbTmPCcfxQTHX89lrMK5X638z`0j%eVkZ3pZWU&w<3DQdVD)h|ALRw_$RQ>xnsk*8Oyqnp^zxW'
    'eZyjty>9d|*aJWs@(G}dI<KGkT1{2}5rXf3yacJ@6D&xqO)@;yMy?=_Am|ZKk24`XAg5QK4iLExyrs{w@s#VWX0vd0h3q$yNC+C)'
    'p7=0I)o}HQN)RBnBI@3K2Y$5&`~b>nEfcC$obAVvcC-+;Ovb1Ax3afrHyhGp`MT$L8rF2}Q}52mYe-zX(o!l+v-KOMY;*va@GhD='
    'E$#i~U>RbB4mmz#c8MdQ=M%>*{r#jnPjm6GPzZy3<RTi-Dls21^V>h45b~?EZy^!aO=0`@(tN(Ioia4nsUCwN5ZUau%uJip3bPJ@'
    ')6_yDk(v7Wi699WgId<)ww(2!|0Y8LpTy*%vvq7O4GfKp6-fI)Cfu|x5X#P+_S@y&E6n%76thNR{)`m>FN$o<B5f7-l48;DZa6wv'
    '(8I-EX=d0N*?6GxP*Q`eDym1q;iRH9U;)6)Y?DxDEd-#?xC58462dV<j}j=&^SE72rzWIg=iE6}ZxjB<tH)Nkc1rY41dt-l$2$$N'
    'e_w-FYN|6p+j2VTRYrN;b=|hVMT)WwMmN9`NiU_M5!MCcgM!<e#7t4!$;Fe!C5Ob5^hSy`<ttEDz}}^o3N?%yemSp0AUWMg-E^Vs'
    'n0l}|xv=#8#W+nt)e~i}wDvpZEFYxV?<?zI2CuG%3lh#d$hvtL&m855GiLbxhfyM3SM<n>svq^cOL%Y|wM6YzfLkt0e#j;Nu!5AW'
    '+;o#ONf!AW!Z_SV3h|kViz_8ncGe$8ch|$~sC`7nOF%vjD{@8d1qM+idc_4&2>14f!{_syqzqxn%eni+wuX`)xrjV<@fF%da846u'
    'm#6qPHE+eS4IzrD7n{}2YM5q=*T%pq_5fD-kC7GKGh4by*z`c)0svm^rx^DIlethQoZE7_ev07G8YheJBh?}lGb#kx#eL4t(O^QU'
    'Uzkh^BLg@^xdtR0UIv`cv2Mg=!vixq>8CQrT8Rw{|7Vp1GI&gA&X~|4NvZJ^w8wL<ViN254ikMM7i0)p=~(LGYXV1%dUE~|8HSsg'
    'jzyv9VnAbe@lX&Inpu7YCI3*XAdCN%<pPBgMKLmykek1{rN?3<@U9XP9*sZ0<UhnmSda`2X;%@&!Mw`pPEmi}a9p+O8ubq3`p10a'
    'rv{MrF?AX@HpAXQhw<cRd~6B57q$|xv$SGw1+HjoWNTU+TpVPM)&ZA~ece3hmRyDnLwM%Hl^itL6;g!B0O~AG8~}O!b6!WmX2r{t'
    '7VO!M);DfF<tqVw$JypnBz2F_3oUWRc8VgYNZvh|#hJ|%tf*)s)|KGx^W@6Nt;hsf5Wkx~8#2Stpj2Ypm1>HbXI_ezdzW{u*P%0#'
    '157M|wlb}Ww2L6T6T0}6Xv<B<M`KJ&d7sZS25Nl!&>sdABWH=56|LJX{~X?+zDYG~LNjj%X*XWO!hzJ{Y*eNO{18uKz+egal&3Lt'
    'XTy$aMU6BAXsije_$Q&vj<HC3s<B*RCXk2;;SWpbS^j;TP-pge;rI`xVrK(&LMByma!@_x2BboGQu!w^E9t*OdRzbuWmmhOT=zLW'
    'grUCRMyO<=Bv448LH=bgpI6ae+ZJz*AE?;K%q;{#H3HsbUMj$hqLoO>{s@9gg_1s#-<6ZuYsx^Xd!5Lmeh$9|1vP><I!o95J1*16'
    'Z3n#{w;f0ySegH&Q2m<+1lNQ+RH;Yq+X}+<rR*ym)pOhBB$ps1SrQ9B);O?reALNbCivE<7_f|8o$-Ia8Yvxu@+v6SoPZ3V-aB<O'
    'X^wMl(*7%P!GWp7h)U3ZmuvaTE;1bZGJB-b^I@P((SC0T;<n&ps&6rASjP5Mr~K+Wyr>8F=z2`Deg*t(pK-o36djBArPP_?4gIl+'
    'RlFz1MqAeWIAo0<<K{)0en|u+U#GS#XzuCNc-6oiTk8eRTG;y>S6&pGfA^>7`iSJb8vCbk<~(4SO++OZWxlI#szOdpOW(wS+n}dI'
    '+BoM<G;0v9u2z_*7TI3X2Qd&f!_>5_NAMs!1YG?!_?L>>S%t?w&z-u#J1WD9gj)YoayHW0oX<&$lOpMS!FU4Wqr=BtGN1i*#2#TP'
    'I#-KsBD<fFC{Ld^D4eZfl^+f4qI+@~!XuN115+WTM(U?EDMl6HN=w=+{Qjs=Uc4w0Z^sw=YljjkVFZXw4;l+M!Nk;E_`_z_6}KF1'
    '%$bHXn53KfXL;}u!_c+m0k~u9vvd)!{+x5wHZebM)0Kn&`_9?n%Y$qMWSHt1^lYJzLkbhiy$F{OsY*U_qK2wy4{aj)dj<T21}>7X'
    'ZTg+Z?NHTDGh39TF`4@;>o?`Y;{vdCGu$m6Jj4!nFcx6zH+&tooN=^aLpbJ<kqU%&4wh7|$~M-4ZmM<Yclp(khB0Q~avMg&zMjJP'
    'nm=tp(72C_B0J=w$Z-p7AdnuUGtqHiSi1X$xuts$)Xs@6r+Wq|pt)J@(v^6VJcWMQKV*uj2B3=T<f40H-zdfDd@2^S?MxxxDAc-2'
    'oR-oiCAsM{1k@Hl2`(s@H{9jRzJm?()J{{46=nnrQrvc3Wy2wuQSvc=$HSJ8(w~4U1ZMLjDNP*!NM5NFa5VH$Dr3vX9+sZxW+w7~'
    'pF0iXo}1(nIF;q8DfU=%XuK9pN^1H8eKOBm8RUOfR4`r>fb-760RG{rNuo}~hv`o(aE?+(Pt)EA=<~*h%@7mMzw4}6(=S^k53nGX'
    'qt;ANc)0Be{Gu^pSY`u0=ATgf{}?SQ^h9lkNLn~yMZuH|@E{VBreoydRSepQa23=K&>1gF%$*+diuxLdb^}KnF2l?&>?5eltAR62'
    'NKIhR|4>~b12*qQ!=2(WJU-!OKM7jc@j+e?e)2o6!$2FHxy-5%W(U@yfKIL2G^8ggLXrrgrfCh5yTQjuBBC9=N`MQ*VXp^y6|pPZ'
    'Z9s{op15hyBe)<lUQ=8BMKWps3JM@^cJK2Zs@bwbJ_S+gE+=)Igc-34<*7Sn+c->FUV6~K9bFyD*Yb8a;#+MUISgF%ZCcE^d(LSM'
    '!IsBpZFaD3WXPJH@Xd^Y_<xD^CstEranpCbHBOKH1sR3_-;-KDY)cV!ss@J$%Jj_UEcZ@m%pZWjlXhJnEU<J89+6+>&C+gK!=%;o'
    'iw*Ij2lJ33pe;jJ_@yV5&=b}$yM@PgVP(O-+NMTh(?+%dsv$Z<rtR=m*(<Ux++X@*RUq}d#cHo4iBLh9Y~IA@{qVTRq3U-pppBa)'
    'Zh@myZ?-JDFt17_2ex925#$x|iZTmGd3#ac7HJxeh7J##28fdlsT)K!)y;xVP7!uVIl9an(U^*7m5Bq4HM}`PUV30b$1-I0^!z9Y'
    'qRl?qI6^D0#;TpK_7E&iE})jpjEJ<|E-HQtL9?h>2|iEBTUV+DIoBGs2XHkhE`c5w9t#dMH6-_yzI7GLZ;NZoKS4c4*3j>cn?L4`'
    '2U~_P&g^G<Txoy2){G=&9juH!FDm574>>CVAhmwb&qE*YJ7)WJseWCniw;nk*tEN(5YKkAsgx2B_0h!5McjR3YMz<Fpp5%aFA|gR'
    'OQ6#cMun*^*IJ<m1eN0wiT%x=tFf$|oXzA((4?2+e`TfcPGR2NoGERwGl%ly`$1thG6@s(@j6ThAJ`#T0-b6Lm7bU-`f+D#U}KCf'
    'VsV}6%tZx<9c_akRLcbgX`ZTsBaM-PuUd9=2|)+x4Yb;{x>c0xR`fRWLfGPDS4l;#jHenGq_jfbN=r4UThq~tz5vC{2%U_83vt4}'
    '>A=HtQu72z>YAL})bjeZMfRpx>rq=`27s6qy0lJeU2a023WjN$mKNB82Unp<a!eD@;VO?+yQ|+CLUkIbu-}xhpi4s^pnIW3s#AHV'
    '-`QqdLj8pdaDH{ks5GZCYwKDxXz_p7`wH6+JkYtYMm81Qc+^K3+5X_VqdEz*z6Dk4cFwlUG?o%+atHt%$6B0sRc~Ads`4gTX04a`'
    'ahQH+DQB4Kfaz10_;Wq$J1)bMVa$rk7Q9SJyg;l+U|phtQZsbmtDo+rb^)9sg$3R&1<}J3z&nqYSOPF;$Co8kmF{k}q8L}qOy^k-'
    'j)S*8EIsMhcGy?(W_ZQAE@HqebqW9@8%|}6B4F~_32+l^>)la|RlC_SzHsEI(wO%lN(zOu?`oPGtOgt%W)t~MWPo7Qmy@_cxs1oP'
    '&r=k_YMN4^a`Kw^CPr}@ldFa$cqsP%iA56{P54h&llr7&QlKh&vSn#sW0&5!VTMPaSj|Ys`GVFzGjw%ey{TPVv>blv?qA^<jRPe?'
    'xB2Ghzwk}euOyzY7=ni37A-mfu6W3Xx}iq~cLi(SuN*pvY93;<b*ByI*ZLw+5pmX;TfTXiWj&jyh-9xb@u=3Ul*es<RB;M8q8PDM'
    'sh+ypp^Y6zEv>)k-@3J5b+FN`HxJl&Q!i>d-8`75-Aaezo!P_E!o>@aiQ_{+|4k>1^t7kAIun4S98YghY$|k;Hak$s@a6i@?LxsK'
    'GOUl;h<t8<r=94=z~afUPK<%O0&EY7a=kJv+z4T2%u?L}V-h<G6s=*PlL5vBx{=bSN&yF1I)<2%Y}MneXmy%+k+S4&qGuL`469qU'
    '>#tr^d&vURl8NGJLh9!{f<uFk8evGp{I0E+<_3eG?!w0!Dc~J9%Jm~@2DJ|-5+&a7s$Zl;`4(XE-IUx~7?DW&1G>v9Y@<84hzk0>'
    'FXXrx+ZaNQo3ACZOU_a=#a>eR8wA8I?vN#KBdGWPsl<`cW;|>!M7kSW*JT@VG&nTPdf#<>HU?i+{^D8W<xSC>_AMGlTtT&l8uxP0'
    'QuI)H&w24GBR6?_Jet1!3UMh<x$VM{3##iauwi_6GTMqOG>VX?OYi0U8zpQFZfk^1yzw?zHrp}C!e_o3@9fO)vLP>h>8<*3Ql)w#'
    'jxFCJd-wNqNalta&oy0k<*jz0vqxMHLbZmytO>3wVn1-zn$!ibYVBYSaN{rOviQpG(9$BGE`vLlzLFMeHZBt9jFZgLp*WFGOfRhW'
    'XPuyk#Cq+Inu{IEzW%4x?LV?IUKA!j#ZL=5>hm%%M@Hg~XlIuyl_*9E1qHV2y*E1SFTX00awk0YuHCDH_}JbST$1OY$7cVWXuf;J'
    'r#34?%VIB6%;NA7Oc{lhS0*7k_C#QTs6m1GMgY11>~m9?AInfpf+O_~m2O(qPzxwEbQjQ)VGwo|Tm&T(J!ZDTu}WYrEY1sRbC3P1'
    '&qYS)-StuD@FH0R4i!VgV{?xDFu6Odrlt1gsicgWAaF=74g%CwQ&lDK@9T9O{I{bO-6VHr&+&eBc7+uroulcz3Nnpv&vU#b=a5Ca'
    'psOf+J6i`Ji;f(&<llj3(?Z+Bjm4-Xz2)hX@~){;@-Q9w;$aO7pW1U?MIub9N*}J$A$qx=k#qn6#U425OIlZY00Eby1G4Xj1poj5'
    'n^<bD6c;-%0{{R300dcD'
)

PACK=lzma.decompress(base64.b85decode(PACK_LZMA85))
assert hashlib.sha256(PACK).hexdigest()==PACK_SHA256

def decoded(name):
    f=FIXTURES[name];raw=PACK[f['offset']:f['offset']+f['bytes']]
    assert len(raw)==f['bytes'] and hashlib.sha256(raw).hexdigest()==f['sha256']
    return raw

def rows(name):return [json.loads(line)for line in decoded(name).splitlines()]
def find(values,kind,**match):return next(r for r in values if r['kind']==kind and all(r.get(k)==v for k,v in match.items()))
def boundary(values,phase):return find(values,'boundary',**{'from':phase})

def make_synthetic_stopped_prefix(original):
    """Parser-only stopped prefix, never native execution or timing evidence."""
    rows = [copy.deepcopy(row) for row in original
            if row['kind'] not in ('setup-acquisition', 'reconstruction')
            and not (row['kind'] == 'charge'
                     and row['stage'] == 'native-setup-acquisition')]
    initial = next(row['detail']['initial_stats'] for row in rows
                   if row.get('stage') == 'context-and-task-source')
    signing = next(row for row in rows
                   if row.get('stage') == 'construct-signed-registration')
    lower = signing['budget_poll']['observed']['process_cpu_ns']
    upper = signing['end']['process_cpu_ns']
    assert upper > lower + 1
    rows[0]['options']['setup_budget_ns'] = (lower + upper) // 2
    for row in rows:
        if row['kind'] != 'boundary':
            continue
        detail = row['detail']
        if row['from'] == 'setup':
            for key in ('original_acquisitions', 'original_search_complete_attempts',
                        'known_original_winning_semantics', 'transaction_count',
                        'transaction_fee_units'):
                detail[key] = 0
            detail['native_stats'] = copy.deepcopy(initial)
        elif row['from'] == 'receiver':
            detail['native_stats'] = copy.deepcopy(initial)
        elif row['from'] == 'audit':
            for key in ('original_reconstruction_records', 'original_target_miss_reconstructions',
                        'original_winner_repetitions'):
                detail[key] = 0
    for sequence, row in enumerate(rows):
        row['sequence'] = sequence
    for row in rows:
        if row['kind'] == 'boundary':
            rows[-1][row['from']] = copy.deepcopy(row['detail'])
    return rows

class NativeMinerReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='w1-miner-reader-');self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'raw.jsonl'
    def native(self,name):
        self.path.write_bytes(decoded(name));return reader.read_miner(self.path,reader.options_from_args(FIXTURES[name]['args']))
    def write(self,values):
        for i,r in enumerate(values):r['sequence']=i
        self.path.write_text(''.join(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n'for r in values));return self.path
    def reject(self,mutation,label,name='maintenance-cap'):
        values=rows(name);mutation(values);self.write(values)
        with self.assertRaisesRegex(ValueError,label):reader.read_miner(self.path)
    def test_all_exact_native_fixtures_use_full_scalar_replay(self):
        expected={'setup-zero':0,'miner-zero':3,'maintenance-cap':7,'zero-paired-cold':8,'screen-four-specialized':27,'budget-cold':11,'miner-late-proof':4,'setup-atomic-tail':0,'setup-registration-tail':2,'four-ancestor-all':31}
        actual=reader.parent.work_oracle.verify
        for name,count in expected.items():
            with self.subTest(name=name),mock.patch.object(reader.parent.work_oracle,'verify',wraps=actual)as calls:
                result=self.native(name)
            self.assertEqual(calls.call_count,count);self.assertEqual(result['retained_proof_records_replayed'],count);self.assertEqual(result['raw_sha256'],FIXTURES[name]['sha256'])
            self.assertEqual(result['total_process_cpu_ns'],sum(result['phase_cpu_ns'].values()))
            self.assertEqual(result['total_process_cpu_ns'],result['phase_boundaries']['audit']['end']['process_cpu_ns'])
            self.assertFalse(result['limits']['minimum_attacker_cost_established'])
    def test_real_zero_setup_and_zero_miner_are_distinct(self):
        setup=self.native('setup-zero');miner=self.native('miner-zero')
        self.assertFalse(setup['setup_complete']);self.assertTrue(miner['setup_complete']);self.assertEqual(setup['miner_status'],'setup-incomplete');self.assertEqual(miner['miner_status'],'miner-cpu-budget-stopped')
        self.assertEqual(setup['counts']['original_winner_records'],0);self.assertEqual(miner['counts']['original_winner_records'],1)
        self.assertEqual(setup['counts']['research_proof_records'],miner['counts']['research_proof_records']);self.assertEqual(miner['counts']['eventually_native_accepted_from_B'],0)
    def test_real_late_proof_is_still_received_and_audited_without_credit(self):
        result=self.native('miner-late-proof');self.assertEqual(result['counts']['research_late_proofs'],1);self.assertEqual(result['receiver']['eventually_native_accepted'],1);self.assertEqual(result['counts']['eventually_native_accepted_from_B'],0)
        self.assertEqual(result['counts']['miner_unique_complete_by_B'],0);self.assertTrue(result['attempts'][0]['native_accepted']);self.assertFalse(result['attempts'][0]['within_miner_budget'])
        self.assertGreaterEqual(result['attempts'][0]['native_admission_completed']['process_cpu_ns'],result['phase_boundaries']['miner']['end']['process_cpu_ns'])
    def test_real_cap_and_budget_terminations_have_distinct_evidence(self):
        cap=self.native('maintenance-cap');stopped=self.native('budget-cold')
        self.assertEqual(cap['miner_status'],'safety-cap-censored');self.assertTrue(cap['miner']['safety_cap_reached']);self.assertTrue(cap['phase_boundaries']['miner']['terminal_poll']['permitted'])
        self.assertEqual(stopped['miner_status'],'miner-cpu-budget-stopped');self.assertFalse(stopped['miner']['safety_cap_reached']);self.assertFalse(stopped['phase_boundaries']['miner']['terminal_poll']['permitted'])
    def test_real_incomplete_registration_candidate_does_not_change_active_balances(self):
        result=self.native('setup-registration-tail');self.assertFalse(result['setup_complete']);self.assertGreater(result['setup']['transaction_fee_units'],0);self.assertEqual(result['setup']['transaction_count'],2);self.assertEqual(result['setup']['native_stats']['height'],0)
        self.assertTrue(all(a['balance']==10_000_000 for a in result['setup']['economy']['accounts'].values()));self.assertEqual(result['counts']['research_proof_records'],0)
    def test_real_four_ancestor_bank_includes_all_historical_parents(self):
        result=self.native('four-ancestor-all');self.assertEqual(len(result['templates']),8);self.assertEqual(len({t['parent']for t in result['templates']}),4);self.assertEqual({a['bank']for a in result['attempts']},{0,1,2,3})
        self.assertEqual(result['setup']['native_stats']['height'],result['receiver']['native_stats']['height']);self.assertEqual(result['setup']['native_stats']['tip'],result['receiver']['native_stats']['tip']);self.assertEqual(result['receiver']['active_chain_growth_from_research'],0)
        self.assertFalse(result['limits']['arbitrary_fork_forest']);self.assertFalse(result['limits']['mature_rewards_or_tip_throughput'])
    def test_actual_zero_paired_producer_is_original_relation(self):
        result=self.native('zero-paired-cold');self.assertEqual(result['options']['arm'],'structure-paired');self.assertEqual(reader.arm(result['options'],1),'blocked-zero-integer-paired');self.assertTrue(all(a['task_index']==1 for a in result['attempts']))
        self.assertEqual(result['setup']['hot_preparations'],0);self.assertGreater(result['charged_stage_cpu_ns']['miner:arithmetic-prepare'],0)
    def test_missing_end_rejected(self):self.reject(lambda v:v.pop(),'RAW_COMPLETENESS')
    def test_unknown_row_key_rejected(self):self.reject(lambda v:find(v,'available').update(free_credit=True),'ROW_FIELDS')
    def test_missing_immediate_availability_rejected(self):self.reject(lambda v:v.remove(find(v,'available')),'MISSING_IMMEDIATE_AVAILABILITY')
    def test_false_full_flush_label_rejected(self):self.reject(lambda v:find(v,'available').update(full_bytes_flushed=False),'FLAG_TRUE:full_bytes_flushed')
    def test_availability_before_full_proof_record_rejected(self):
        def mutate(v):find(v,'available')['available']=copy.deepcopy(find(v,'attempt')['generated'])
        self.reject(mutate,'AVAILABILITY_BEFORE_BYTES')
    def test_late_credit_cannot_be_promoted(self):self.reject(lambda v:find(v,'available').update(within_miner_budget=True),'AVAILABILITY_BUDGET','miner-late-proof')
    def test_receiver_credit_cannot_be_promoted(self):self.reject(lambda v:find(v,'receiver').update(from_within_miner_budget=True),'RECEIVER_CREDIT_BINDING','miner-late-proof')
    def test_target_miss_cannot_be_deleted(self):
        def mutate(v):
            a=next(r for r in v if r['kind']=='attempt' and not r['proof']['target_hit']);v.remove(a)
        self.reject(mutate,'AVAILABILITY_DUPLICATE_OR_DELAYED|AVAILABILITY_ORDER')
    def test_truncated_full_proof_rejected(self):self.reject(lambda v:find(v,'attempt')['proof'].update(proof_hex=find(v,'attempt')['proof']['proof_hex'][:-2]),'PROOF_HEX')
    def test_forged_target_hit_still_fails_full_relation_replay(self):
        def mutate(v):
            proof=find(v,'attempt')['proof'];challenge=bytes.fromhex(proof['challenge']);task=bytes.fromhex(proof['task']);header=bytes.fromhex(proof['header_hex']);target=bytes.fromhex(proof['target'])
            for i in range(1024):
                trace=hashlib.sha256(b'invalid-native-miner-trace'+i.to_bytes(8,'little')).digest();ticket=reader.H('ticket',challenge,trace)
                if ticket<=target:break
            else:self.fail('bounded deliberately invalid trace did not hit')
            wire=bytes.fromhex(proof['proof_hex'])[:-32]+trace;reader.parent.work_oracle.precheck(challenge,task,target,wire)
            proof.update(trace=trace.hex(),ticket=ticket.hex(),semantic_id=reader.H('w1-cost-game-semantic-ticket-v1',task,challenge,ticket).hex(),block_id=reader.H('block',header,trace).hex(),target_hit=True,proof_hex=wire.hex(),proof_sha256=hashlib.sha256(wire).hexdigest())
        self.reject(mutate,'TRANSCRIPT')
    def test_actual_node_or_verifier_in_miner_flag_rejected(self):
        for key in ('native_verifier_called','node_called'):
            with self.subTest(key=key):self.reject(lambda v:find(v,'attempt').update({key:True}),'FLAG_FALSE:'+key)
    def test_receiver_phase_cannot_move_before_miner_seal(self):self.reject(lambda v:find(v,'receiver').update(phase='miner'),'PHASE_RECORD_ORDER')
    def test_duplicate_native_admission_rejected(self):
        def mutate(v):r=find(v,'receiver');v.insert(v.index(r)+1,copy.deepcopy(r))
        self.reject(mutate,'RECEIVER_ORDER')
    def test_sibling_acceptance_cannot_increase_active_chainwork(self):
        def mutate(v):d=boundary(v,'receiver')['detail']['native_stats'];d['chainwork_hex']=f'{int(d["chainwork_hex"],16)+2:0128x}'
        self.reject(mutate,'NATIVE_STATS')
    def test_phase_delta_and_global_endpoint_are_independently_bound(self):
        self.reject(lambda v:boundary(v,'miner').update(elapsed_cpu_ns=boundary(v,'miner')['elapsed_cpu_ns']+1),'PHASE_ELAPSED')
        self.reject(lambda v:v[-1].update(total_process_cpu_ns=v[-1]['total_process_cpu_ns']+1),'GLOBAL_CPU_ENDPOINT')
    def test_boundary_cannot_skip_receiver_or_teardown(self):self.reject(lambda v:v.remove(boundary(v,'receiver')),'PHASE_RECORD_ORDER|PHASE_BOUNDARY_ORDER')
    def test_stale_budget_permission_rejected(self):
        def mutate(v):
            c=next(r for r in v if r['kind']=='charge' and r['stage']=='complete-proof-and-ticket');old=next(r for r in v if r['kind']=='charge' and r['stage']=='fixed-selection');c['budget_poll']=copy.deepcopy(old['budget_poll'])
        self.reject(mutate,'STALE_POLL')
    def test_negative_terminal_poll_cannot_become_positive(self):
        self.reject(lambda v:boundary(v,'miner')['terminal_poll'].update(permitted=True),'POLL_PREDICATE','miner-zero')
    def test_budget_zero_cannot_invent_setup_completion(self):self.reject(lambda v:boundary(v,'setup')['detail'].update(complete=True,status='complete'),'SETUP_OVER_BUDGET_OR_INCOMPLETE','setup-zero')
    def test_cap_cannot_be_called_budget_exhaustion(self):self.reject(lambda v:boundary(v,'miner')['detail'].update(status='miner-cpu-budget-stopped'),'MINER_SUMMARY_BINDING')
    def test_bool_cannot_replace_zero_count_in_all_summaries(self):
        def mutate(v):boundary(v,'miner')['detail']['attempts']=False;v[-1]['miner']['attempts']=False
        self.reject(mutate,'MINER_SUMMARY_BINDING','setup-zero')
    def test_bool_cannot_replace_stage_task_index(self):
        self.reject(lambda v:next(r for r in v if r['kind']=='charge' and r['stage']=='arithmetic-prepare')['detail'].update(task_index=False),'NUMBER:task_index')
    def test_phase_origin_rejects_false_for_zero(self):
        def mutate(v):boundary(v,'setup')['begin']={'process_cpu_ns':False,'wall_ns':False}
        self.reject(mutate,'PHASE_BOUNDARY_ORDER','setup-zero')
    def test_fee_total_rejects_equal_float(self):
        def mutate(v):r=find(v,'setup-acquisition')['fee_receipt'];r['fee_total']=float(r['fee_total'])
        self.reject(mutate,'FEE_TOTAL','setup-registration-tail')
    def test_unconsumed_registration_tail_has_strict_detail(self):
        prefix=make_synthetic_stopped_prefix(rows('setup-registration-tail'))
        reader.read_miner(self.write(prefix))
        for value in (2.0,False,True,0,1):
            mutant=copy.deepcopy(prefix)
            find(mutant,'charge',stage='construct-signed-registration')['detail']['transactions']=value
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'REGISTRATION_CONSTRUCTION_DETAIL'):
                reader.read_miner(self.write(mutant))
    def test_paid_screen_requires_every_candidate_and_real_noise(self):
        self.reject(lambda v:v.remove(find(v,'screen')),'SCREEN_GRID','screen-four-specialized')
        self.reject(lambda v:find(v,'screen').update(score=find(v,'screen')['score']+1),'SCREEN_REPLAY','screen-four-specialized')
    def test_paid_screen_cannot_claim_free_noise_reuse(self):self.reject(lambda v:find(v,'screen').update(noise_passed_to_producer=True),'FLAG_FALSE:noise_passed_to_producer','screen-four-specialized')
    def test_parent_template_cannot_be_substituted(self):self.reject(lambda v:find(v,'template').update(parent='00'*32),'TEMPLATE_PARENT','four-ancestor-all')
    def test_selective_task_acquisition_cannot_be_relabelled_shared(self):self.reject(lambda v:v[0]['options'].update(acquisition='shared'),'ZERO_ACQUISITION_SCOPE')
    def test_registration_signature_is_replayed(self):
        def mutate(v):r=find(v,'task-statement');r['statement_hex']=r['statement_hex'][:-2]+('00' if r['statement_hex'][-2:]!='00'else '01')
        self.reject(mutate,'SIGNATURE','zero-paired-cold')
    def test_fee_receipt_cannot_drop_native_cost(self):self.reject(lambda v:find(v,'setup-acquisition').update(fee_units=0),'FEE_ROOT','zero-paired-cold')
    def test_missing_original_search_reconstruction_rejected(self):self.reject(lambda v:v.remove(find(v,'reconstruction')),'RECONSTRUCTION_ORDER|AUDIT_COMPLETENESS')
    def test_reconstructed_winner_never_adds_new_work_credit(self):self.reject(lambda v:find(v,'reconstruction').update(new_work_credit=True),'FLAG_FALSE:new_work_credit')
    def test_known_setup_winner_cannot_replace_miner_proof(self):
        def mutate(v):find(v,'attempt')['proof']=copy.deepcopy(find(v,'setup-acquisition')['proof'])
        self.reject(mutate,'ATTEMPT_NATIVE_TEMPLATE')
    def test_false_public_authority_or_production_promotion_rejected(self):
        self.reject(lambda v:v[0].update(production_activation=True),'FLAG_FALSE:production_activation')
        self.reject(lambda v:next(r for r in v if r['kind']=='charge' and r['stage']=='context-and-task-source')['detail'].update(public_task_authority=True),'FLAG_FALSE:public_task_authority')
    def test_options_match_external_pin_and_reject_bool(self):
        self.path.write_bytes(decoded('maintenance-cap'));expected=reader.options_from_args(FIXTURES['maintenance-cap']['args']);expected['parents']=4
        with self.assertRaisesRegex(ValueError,'EXPECTED_OPTIONS'):reader.read_miner(self.path,expected)
        for key in ('parents','max_attempts','seed','miner_budget_ns'):
            changed=reader.options_from_args([]);changed[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):reader.validate_options(changed)
    def test_duplicate_json_key_and_symlink_rejected(self):
        raw=decoded('setup-zero');self.path.write_bytes(raw.replace(b'"kind":"start"',b'"kind":"start","kind":"start"',1))
        with self.assertRaisesRegex(ValueError,'duplicate JSON key'):reader.read_miner(self.path)
        self.path.write_bytes(raw);link=Path(self.temp.name)/'link.jsonl';link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError,'RAW_SIZE_OR_SYMLINK'):reader.read_miner(link)

if __name__=='__main__':unittest.main()
