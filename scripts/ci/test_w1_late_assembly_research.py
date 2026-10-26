#!/usr/bin/env python3
"""Real cap-only native fixtures and adversarial provenance/accounting controls.
No fixture is a simulated successful execution or a performance comparison.
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
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import w1_late_assembly_reader as reader
import run_w1_late_assembly_research as runner
NATIVE_ORIGIN = {'scope': 'unfrozen cap-only real native functionality; no performance inference', 'binary_sha256': 'e89bacbd8aafc6f4141d4c81a8a1c818e960eeb9ebd1ff33be7bb1b997b9c7f6', 'source_sha256': {'trillionnium/crates/trnm-pon-node/examples/pon_w1_late_assembly_research.rs': 'efd95aff69f36be1ae2d3c54d07bc0e346a92157f43c6078286089495661c1bd', 'trillionnium/crates/trnm-pon-node/examples/support/w1_deferred_producer.rs': '353bb9828ee899713090496da2b064b54ad465a924adb79116353c428d23d206'}}
FIXTURES = {'p0': {'offset': 0, 'bytes': 2509, 'sha256': '62e19ea488d1dfc4e7d5f4a8bbf5d336b5e0c0584d8d4231d581007d1edb60b4', 'args': ['--setup-budget-ns', '0', '--max-attempts', '4']}, 'b0': {'offset': 2509, 'bytes': 268647, 'sha256': 'c346734da090cd3b6cb54a209549acc6f5c07063da9284e9926b3ed921a6e1b7', 'args': ['--miner-budget-ns', '0', '--max-attempts', '4']}, 'eager': {'offset': 271156, 'bytes': 1073901, 'sha256': 'f47d6645f0dcf0d80fef13090abeb9f9999226e6d373120747ce6f248f27e72c', 'args': ['--max-attempts', '8', '--seed', '4101', '--mode', 'eager']}, 'deferred': {'offset': 1345057, 'bytes': 1073909, 'sha256': 'a45e4bfefa9aa2480109b781d086c1679e4ddb118f61237610cba7bab45323b1', 'args': ['--max-attempts', '8', '--seed', '4101', '--mode', 'deferred']}, 'late': {'offset': 2418966, 'bytes': 369564, 'sha256': '29bc069508f74a71aa66762ded94e280eeb01f764fb14f2a375b12212a3daef7', 'args': ['--miner-budget-ns', '100000', '--max-attempts', '4', '--mode', 'deferred']}}
PACK_SHA256 = 'c3f0633acbfe9096b0608bfc37dfc66abea8638a6de02ab586709d3da4a86828'
PACK_LZMA85 = (
    '{Wp48S^xk9=GL@E0stWa761SMbT8$j|NnhQqFn$zh=^xIJ*N2CAQwC=d!Yj~9hz^6XDaVZ;&@aeS|tbnh=vT#^{|+}BtSt_=)v(O'
    '@gYHrmrfzujN<qLn+P_y^!1vjYXDJFzle&*f+`cw5f^<N(cA{GNdc5vSw;R@`T)n$=0m$_zOe`%PO|=;wl$|sD!=EDQv^D4cwohe'
    ')jh&+ncjN;3bpqLbI7ZONVPusQ|96HzqQrXqt>s@w)cnhVo)Qr_cR;o77D1&&?Gv9Az(<Dc*a1mA|7n|V<L=~hyu0Ws&_q`cu;^6'
    'x~9LYb`ckAThv^d6B%}Ekj=|I>O4s$<>JgZT3-'
    'RtbHzbey)ygI;#=ZUARTYRL*PJ%o3}Z5N%P|qPK&m+$J(}3a)G^Ff>UJV2elmIm4!9DN|g`xTic%~gdgSc2T7eOTNLMKm2C)vP3N'
    '9Oy_n*E4-'
    '>B8{a{4n?OkriHP6^XPD8O`M^iUz(rb@RL#fQLhNHF;%VKlb`i(<cL$%7vYco?JRSZo5deLUT7$wmL#A}Ntb2u72x|s0MNJjg(5}'
    '$GUGp&H+!&>2=E$5o|kmcYJwjeRTss0{j&NgjugLBUM2rAZF`oJD$CQnrvrJi9xNmgkqbJN~Fl;&VN-'
    'L|x{wtByFyZ<GOpD28V&^*T!8a@NeB_BBpaoIi8C7(Z>87_#Cu$l@$Yo!^^OHYA_({lv!7=Wo#=aLPRJL-'
    '8Mx4C{OS#O)xL8r%e1Ra$=h6x$}2r1@@+P?*8?Z$ynNR+e&(E4uy_dW;Vsh#+q#?+;+SYJWOYp_n8AWMfcsulusXv7Oz4iB;)mpY'
    'mqSVJ)L!3F5z0)vm)6deMpl|SDy?y#ba@|0xPcD8RmtV;nq%Yrg23vsho5Vw(0PPd;Y+i-'
    '^0aRCL44(6Z~`lQ$4fNx_gvodkSB~Mux{oEA`RX|2a4H)B1PW}tzGQ{v=gDClS;QZ(1JN`}MH}mNNH%ksFnra#;j*zn1A<+{vn6?'
    'Hxt&S(Gc+}Ej{QVG+e8H85Zr`-?g^6x6a-'
    '}fsQ8z6kx~37(ADNwE+qeg!7Z?|c$9HXdQvdslFDML`Jl`#I<%<Uu2x5$<E|I1NNpy^Nrb0sMI$$RObY8d-'
    '+%|uH{91AWp|NGCE_%gmcALR{)?)AJXpD>tjn($V<Z{KHniX+e=|8>?xJ{nvc^HzHG^9%9=-'
    'Q_9i<AX8ycGMvl3SxfMi(8EEs54Xfk8D!N}{|}15VZ&_=Um{w=J=0(k;oXg)KB|jJP1KaXUegOx|p@)d^wK13Xl|?1FK6mCUM!vk'
    'WC2bGFTR(Pl05&2Sw<30bplk2j1$@^@pr8Juu_@7@E5)K{sRw|P?ee2Uq37P*0nT8k{w--I#>!1e!%t6k@u`fLWGq41vl<8pD<Qy'
    '&b`T0xsSZPn@@=9~I5vK?$y@XM8JZQn(FBZD(IS4EB5Y98&87WBjLC?-'
    'lg1f~EASRq%LqkU{zAn;C=w%O@WsjR#w=+fj3`?VEH7w;5lbmD6hPtt!CS*^Lfm-'
    '$pRtwh??9(&$2{8D7z0)H{XEU;iF5P|S~0Xn<naMv4rRqqc=+lgLiob9xzP0SnM_+k6E1Kw!q)@VY<FDkSYGLtBJGE%w+yK^M<0M'
    'sdW#hSwGJZmSfsVxa{Pj`3KD&2#RZdf6AdhkydwMf$#+I8fHo-'
    'LOMJhXnsla&SA%G(xU3|GS;p&kC~7T6HStvBCs)m5x=B<b;=pHveHgV@`2J=M%dN-_d)j`mNt@!D^Hz~B3wW*A_+Ve5w&Ai*%4l='
    '<nIzW$ncO=&rx>rB;@9?~+ic&Dq;z{K21aZUe$(}tHZ29HxqW8d6~Tzs=(rlN<jB`FLQ3gW3m7lY!c;xB{i3q4*JO+!i)`xlxRQ!'
    'P!z2=^M7lTs`R2GX(=0`EI!>+U-&$kMiut%4G9ISI<eRugJ-U9cSx(uq=x;xwhMIm)IMGnK`r!ZVRseMRKRaeB5x^|T7?x2#XLU-'
    'WV}xc^_1)hGyOuy&+$u8H}?mx~XMM#zFn@s$0_`$v3To2W%W#?Hpe{>I%*#oVp%JwdJqaIay=*L{7aBC#5}q`@6yWUlfhcK=#Idt'
    'SUR5iX};<Ue^cUqKt2!OHc(Rkf2q_mYKP%|Kdg!7jv?!+^#Hoo3<mH=_T2u=`;`*muCrb>E_Uf1S?+-'
    'Z*;39&(0`eK#K>{g;O3*W4>!$#zcn>MSh|>;>)qD*rfZ#mA2Jyq|H;%E-'
    'v|h;Dh!>6_yY3VmhHQr80=*@xSwpuFZUUNY7Oq0qN;vn<8X^jx1ETJ_eif5lTf^#7{1TQ3)Ey#rpRe6m`04JYbHM;2m&fVgO)n_K'
    'jR<4&0!J|mVrt#?M@mTdH*N)#}h_jcY$c3AYPTP?`<-8+n7E(Z-f411(Nd!^oX-I@Gsn&Fs&1D`mIGM-A*gn(Nsqdu<LT12-'
    'wydNm=VmPl1N}8rQcIB}}e2W8?EH3p8chSxj0$t0Gym46KVr4_s=Fl^EYH9#GVlDUIny#5g8f+PY$-'
    '}PYVIvy5b(aKJA#)P?Ka|qb0<`fz7|W4XC6EYy13T3KwvWVE!r7VrsyfN^k%gQ-mzT#|+2(>G$kvKPoGt&3WSM~x=dZbX9AjU*lG'
    '$E_cf1YTpQp7dmsz+TfnM8q&e#(LRf5Dn&|N>)D&_lJcb*A7GXK9nA*ghlRIxUg3$qML(~$7Wht3#x;s;r<jFuQm+iAp@I6snZ>y'
    'w_$Ihmk2hH#2;P}znm6II32Jv_<aKye^I9khg?BTq3F$5BQEZ^1>g^uNd^s<w9k!otn#Zx!-'
    'jaQ~NGtr@V!J(TVa7oGG$)}dCA#9{7Netw7__f2q@k$ThKOTkqN<Fs3fx#kK7XC!ou>x+&4n|&upv7XuAVJG+=3v_TT#U0B`b`BZ'
    '?Cd(btbAV_3H6?OTRKC&TkHl0bT3O2yz!fJ{$b<}F4yY9lO4HoFaN>0D?%<x&2m2I=Fg>#kxJ?>GugVA4aonNm#ruzI7jd16Q3`A'
    'Na^qv`Rur`RTJN2D(7mKtlMuBJFJnbL#<^aujjJd8cyT7$=#$A@a;O!;kP%jr1mEpV@n>dhu4~Iit_)4M)Z3W!<WEcdB5HpTY#ve'
    'rWwL`m!f^nbWWUFU*h`pSf6tpQK@U)Z#kg(I^aTM6i}Z#9+j8PLQ&912gd5p#(#|wP{x*#~=z73XT{AfEtE9>tBzJc;tU#m5L<rl'
    '`wKAK=P%Pp)-'
    'HbCj8xez<`Zt?2V(k6wVK0IKa`v}UXRIA7_iYYX+$2MctDG05T(=Hdp+~(`JRZK5cuo&_xu{`+)ZNJo9R_2kxo6Y{nMF;S2^bC9z'
    'K0(zp~STzdapd)JxS`#wb}FvSQhx!&``*u{Q9^|eR8dLwm_5cbogz*4~9GHQlZ!&uuawfMAqj+`<<_6;Rl*1FqTi_VOP|#K;e%Mn'
    'r`k!Ak<6h`S0aoe?C`H4$ekdSE}VIx_GFtou&fr*JtXCrlQ6G=-m02+RB+dnwf<v-'
    'E$tua)PCn0n&>CoY_%R<(Wmp36|=`>Vo5nN^faM2I+-3*}V5nltss2-'
    '&$jS){J(hS6i|q1vecwgBQ!VgA|G6C<I8M4JP|4%A(<oGgRnezl>e?XF5mKhz-'
    'a!L=N_s{%@Yl<ETtBusu(lSsCaGL3K)SKiVr<U*3mfEOms8<2zRzUyO<-V#{t>tHWnd8h?c;LIL1Kbux^nh-0k>T6_kPAv-DBY%='
    '?&!?iXgD`|UgR8E@bmnR<UzBQ)@_MMa00ye0$MGLt_YrJ=g8>ECag#8^&gZMl9sNl5UFy{`YufHbNnEw$2TPa>I6FHGMwyJkPM1*'
    '+Kf|1=A2UF^a3V=@(G_}b^l}PD~1Site+t17B)?IbEp$8-'
    'hVpZg*6=~3W7!T$&WG#}u!JT6h`y!sqCoguAOejuxi0}V%oV;=;6S#$W+>Jr*7Kzk^IFoXZ<j-'
    'Oae6=wE%jL0}4i<Z{pILVPQ(_7gBaH2AQQhg_Xq{#!NcW6Z?bxhv@_`@liG)f7jL|v>DP@h)2@sbdgdV`&>7RikZH~sP4_vjfxGu'
    'aCp=lL7{~lF`%OF|kptVK3B<&G(!5h!8NmO7JZmou@+AiCzL|w58Z^qAe^cl5<$<>-'
    'qK~TMJZAQ^@ALhhzXTO<uggv$P3qk4`fG<27I+8nRc`^-'
    'y8>^?ekh|?f|226?79)$n`=~WjcQ5M{r+L{>mwH|sX&fb@AQOs%rY@SHM{Aw{Pnl&VBnN8z%NrLY8PqAA>+VT`DSz-'
    'd|91Yp>NuYkziYlt4xUuJ$Inh|f!HSOZUR`hQ?H07w)0gbY?wBZLr8h8_M1>sg(bEg@-ht)^I}Sxk8-'
    '}P&n%xQL5)NFulm+fL<AGd>WxdLYS9}`1L(`Kgpa<YmhiqTitvI5hH+#Se2*!T*|r5^I)oP-'
    'W$jf97x9r4yzy(@xrYy3lu;PwQnpCAMu43cBf+RvLJEAS3TiE&&rp5J)5|^SfA}L}MbdMbvM@0oiVm~z=n9Hzaa+soR5^1OTt<2B'
    'nNzA%9=X)ZvKHOrf*u$^7s#()s>x-'
    'XSZ>?<@6qR%n3WBY>js||#BZVT9TUx@Wf4B~$oI|u^L@6XIcvCgZS&siJsjde6+65IyPl5LxK#38bcmC&8V?cxFfBk_Bzd4^g}CH'
    'fGi!@jU73-w#xTO7i-'
    'h5drL}qFLXdXw<Mc&noH)_=C*i<tUb#n;vP=Q#on@S|U>p2Wx;o{upOeUnnEq<%!O_xwr;^w>|1pu}4M>s-'
    '@#Z(8J&w@^(A}PHq(L1K@j>D|=-geOEG@_c><`_R!W~1`(3?oaX|E~%sI>f{yZ)WepNNH{R7GkK47S*jK7j|(Ys3-'
    'TXr21scXGJs>l0i$42C?7QeYq(4el~RC(4j>0MWsg*Afiv9}YS@hj{&lkOEycn42VF*Vty{NEdl7JNJP3dPuTCFc`<b+0Udylf7t'
    '{3SWcXC+1knJ=?w&8ko`FM=L<3z2vG)ZfV@c#yzKkHOA(930*j;^=-4?*rFZPbRyoBEqzh%gzwc6^DkH6aRKbt&-'
    'EztG#nA#FsszQ+uvm@pgemeRL8Kbs&~n}=;Op%O=mFA@k974u5c@l+XQ<DNy$!*6mlbGQiTALi)BDfyU?vFKD<xxZ<```3&QLTW}'
    'B@3i_a`1_z5|`X8c2WGETh}%gX7GrY|#qI$}yLgZ`QzezEH7DsM{z_MvSSTe#r*?~TVdNV`Svn8D^ywa~ONktZgSeAc6#Y^+u$pC'
    'I4%_{US&HF0mrg+E!u9Cgm2I_!|FrNhzAc4Dn7RjnTuqxJoem^6c?f&4|b-'
    'PnaW>Q7=VcXzplw(BOdh|BV|{WI`mQ4w5zQpv`O^tRc?)0YEhpWy@2_v4LLANq&|QC>><n^whrI#xCi%(;!b)AD+}(@~~5d{tQoP'
    'fjalq)u|vD%*)QiiGe6krI$NkcN79i8%;LaS-#P2VDAE;$cAv_Nhg>^qE=fKoX-'
    '{N!sh>#5*%0Q|H_9H!7%pF8vBJvGn}+T4+5zfgMZRG(=b15|^-I$p{;}F(haUtnSh6ztF+p93<-'
    'XJSA_JR|Z1sA<kQ3kTFxQTX1smMX8a4*QgF#E$<RzLhm{dN<Q8QSsO%VIcB%FV=^&jX*iY4mEwV60>K18r%IilFK)lm-cAdeC0s*'
    '!Fg|5g(<_6^b4gI}r2$(NCSD59=<Kp5mD>q0%>RWtxk7{XXz3bMsD9z#OsJqQGs^To_y)Gpn*(N=n(PIV_PIk!fw;Jv2<ud)*(aT'
    'X82I*+TZGn^HD@>xh=%6)ESXhUtDZ!0N6j$>giTH8s$C><r>2ONgUB-_8;BZBR4iIJ5d%g-'
    '30=9X?nQHO4D(C5td+pJ`+4ZH`gnY1*ffl1q`U5`E48f}SNG_Zfu7$5Mc`^n7NJ6r3b6tEUh2bEf%Zs_6k7&q9t9?RALE@A8kT=*'
    'Vy&Q!ltrwDHA~dKc*5l8qd7mXNYDF)JU3~QL0vXINHse8xx}z3HW@U~`4=f?{$!2p#4H82{87@<5`gpU>6IH(|A!oj%A))4PK+#t'
    '1B+V#jFky62pTl^6d^OXG@xN-H5P@QPC(IF+F}~g-'
    'hDx+`yHFn(LNVm^=A!dsas9kRouZO$3VX024b*=c9YLkP7Gc5PQn5*<W<Nx!H<XyT6Q8VQe1Cs@M=SENIb6NwK6xA$=bXL;i<8#s'
    'at%bXPZvdKX+l(<EA?J$WVFPD2^yU-Luv*QRA4`$x!+E7>utjZ_Q0Y91%M{$-DD5W*K$mu9^y~8Nu_=-'
    'HWb9H^|PRO*CSY<O5Z&=!zjxT6${s+{FF^UK87|D>Ynr%_+Irug31mfJ=0r(B|~3L}=8|Ur8aTDj`4P!y*?Xi{w?aOI{DNa%ts4a'
    '0wacsap`S2Lx@aQb{Dvpx#vj24TKZkx1Xx_ZS<p32yHSCrkM)|2eEd^8!vX_JJ;MeIf(AFEG?0$9KJE(os@d4W*j{ti5320EGg;3'
    'MNSY7P?5(?M2fKtOhy55xd~W*R*9!31I#fs~(?W+ts)1_{d%>^Qhd$i5mzxUhkMfR$0O<96F+_;<JdXv(Kd>{$S21_rhpzh!UJVF'
    '&3<_=@w9h<w+{UZ~yNJ<6yYJ_Gn=U<r=z!vDeaF1>O?{kHw*bMv5U={)tBV7ig8rFs}sC1-'
    'x^Q@!X9blzltltc}Wa1s|U!ZV2zuR30B1J4NN<1^r5}Sz@6LJwW{>c?f&YGTgWCf>@_0o1#a=7+v|bXMlXbfO|R{^q0<yk*BcyzF'
    '^PL7`@G-=psWbaomJ#;Ek5O^+PNZV3bojkjYs=O9q-dDJ&+RKb!rkGZ(?`k$8kpvig>wli%byLRWaDj{>Ny5<|bw-qCc7T@4?a3f'
    'Q$LqvsFb6H{lh<3}aG>CBeoL*mR-'
    'O4wRJ>~vPLdAEndgQ=d&cNK&nMiyA{`LD~qR77_}R+#6<{GOYAW*Po%&8guOY*iWgcmos|7)BVT)5Jc`db{{Z`!yhAZ!x)tZ{4s1'
    '^4olUoZQ{#uoe(`z#w=E!=Z+udCzc=DW22W&57Tsz6{ZoX1u6h0;P!_FdBL&$yl6J`U#~LFt<d2q^*)fm<4n{9@$#h--'
    '^1Zxqio@ZCj#n8UD)-'
    'q)n@hw9CljxcyfBoQb&xV@LNjHm0P;v(kA%NTJ5;NM&C4PtOf#Mj#c12rhpk<G`E}EF;3rHUZ#whiRh9%|x00l3JS{c#pkMd{!2;'
    'F}!RNCQRW*AhR!_=y!|$Gr;M4hHf%tC5TMH+3O7u-'
    'b^EVcndOrscTC=LS%ra8+A&ac*W;~igO?tU#YE>;z|Ih7sy(<{;S+<vKy{TQTKZ<TNa;Vh+s|#EB!Q-'
    'H84bh(Gx4+A>g*tSFI+vrl}C4GpAiA)nuC;3>+=Z8M@^Ig*MAc(HpI$JX(S7^OU$fzXu}zFA9e{J$T{*vXMcur_Nc^FIYS(koG?W'
    '^}t7AifxRi!+Wl{g`KuCJ>q23hm#Q_ljq=v3^?9keV+xRydB8@3G&>SJA~4=xQRwTJ2GXZ35YjWh=}k4n4ZjDaIyIkY@#MR7y{Xu'
    'lXN11Xzpw(#Bmu51*DtuXbtaB@>}kS5hJ@qTp%~lx{p!PtdW~&-'
    '>?SZ4A?x6M@UiwMKyX;kCs5^oszu6@}T+Ggb>)&{~rnF0VRNZq994@47f8^J#j~!%CBr%OZHJ|mWk)L{yGVXw_1}DC})py(Wd%=Q'
    'RL(^O@I5f!Hp7wk4zRv9=#PDzfB+#md&AlE#M7byZ^QQdnQSX9VhGoxxOYfX;3jX1g3nfWtP7)v(c39XExc;!gv!T8C>z1mk;5k1'
    'htDchRa~VwGco;`mqP296<Z}?RiT&zJ<orzkdvdwum_m0=1F3edbe?JL9W?lY#4IHl_<{eQk>}{=68<p#;6EC7jYOeg_ke(GdyB0'
    't9C#W1s=JZdA@kzW5~H)<*R!6`JzDqPmq&aG(Ia4&w&#f<3r^Ph&hMnisVK)d~((R8}2BPi9j`>>*$?^Y~2h@^Q8n0Cn8Jwnrtmm'
    '3rCo6NvO8Qo+&Iyp8_--73@QT>Arxlr&xGFpE-MJhdI;S?&NE-'
    'Ws&X=UnjNARJT8&F>dZ;*rT~LW)kKSG|5~DNNnF>mp+?VjrRRSURLF_JC2RD@FqL)~iU_jLo-CYo5{Aeb)kvX^<87ODxURKqPzA9'
    'I5bb7&+Wi{Xby2Vd0l;fn|bZzbHeS@Ybo|<d?&8Fz5r&kE2-F4O#~4Ob|kq)L0?q#FdibvAnN3zlx%5qW%eSjP-'
    'c>!Gn=tr_`EYK<si%IkYtyH-'
    '^a+EXAU^CjRyi+r{B`!(<epTZPxSew{pq+hb5Xs*jDMJ@cCRtU7LaI=VLy#duUXcQZXtRqYheIT$cLkqsiDd3IDQx%l#XRzG%!E-'
    'e5+wGV1phAJ-ncQnapW+9mC2tHUF<XA<tHXoE}<6*4MLpjMo!>|g(86Y?GRmp(CAe#;hx}^HO7EMXBgRs%^pB-Fs5>Vm&|4BgKJo'
    'N7#9R{_I5a_Weg%8y5&xZB*n+URA4V0~?CE0r0*^ws>+~^!$Nu*g@{#eyt4DK!i%`K7<3`CmU<+Zu(d)p0s5XL^zv9Dx)I7Jse&K'
    'Nca{<E+Q?A%GOcHl2s<n6|?;fS+HRT9IdqbVRY%gR45s7M(Ocs@n`Z=LnNw8Z7efNu;!^6ZM~_D$8q6qHGfgDE6N2EpE$i4*hC%7'
    'ayMgIM5*b#>=ICxhc?uX#LBz%cdfP6m*#({&{^&g{Nb^R2P?`pPxA_V+Kq3xs@uKQid8lKRz5C*12&fWAhZ^&?^vq!fDw6Z4oAEQ'
    '5%L4V^M*rX~ASi2C^YP801y)&K(T2jnxR)gc2-'
    'E;TK+hPElgSQOJPcMJSkH&X3XU_g6qd#W(UkxE@drbpsVEEpOfR^oNpXiz@qU7jhyv#8o{kz8m3!`Ir{#SqO3XqKIm*xe^{VOm?{'
    '2dNGcF5?7Kol1*$o8*)gFr*y(wCrjJJl>kkAJ{8M;i~d1YqX(!_cPyRAnzt3Ysk$(e?zaRSYAO@)UJhTg0F4e5*Y`wf@`~Piim>S'
    '+fO6Lz&awCwQ43wEt(XMX*z6XPp1{_R?~hq11Wv6(88<C_5N6ogAM<KwHal~%8cl?w$d+f;f~jj|7Qr)STyeZZs?;}P#H5NyNQ`U'
    '`4G~36yRKim(Ny1yY$c&lA<CL@D&V~{t>4+Vz`X-&Z-'
    'ENJ)8VeE85BeiVc@=x)C?)1iS}4<tk~W_zY=#TSWD$oWom^2i*}k0;dz%lcfE%BZH64r2$yB++J-'
    'q?7(V_H1;$YSQ$0c*8ko@Qj}-XY*w-'
    'P$4IJY@sY9)|AR~h+GE|gfRHMEFdqS`XZ@!yVd76DccB7+9k)RDpD@K$X6&FbkKwB_2Dm>lAcxy^X{mgwKRZCqb-rwgK^i+??qJw'
    'fqlTlNGQ1YVTy=`GM%bm7D=N#991b$$9qBAWU(TXUS@LYtcUAQDWoHRS7oBRhlOo2~6g0UMJ^M^rewkOg|Go1wiXxc*r(x|&*2=i'
    'NeyMwK{u*RD3wNrlNnFRLVexD12F9f<c#%p<OHh%8Xj{_}<;->Cog12<8?q?r<BY{<%IwYe89zLU_Kd#8ECKp2oO?X`)1*-'
    '3RPkxlAA$+4Nw4zk7}$GfUz({-'
    'p>c{t=7wnT;638MtlG0@n!+gr;E5a}I$Y!s&7o!ZDqU74p#xg~8z6NPZrnG^x!?@167v$p35(BO=uQi=rvsUhu2RyENxr4hhYz|U'
    'UK1j)=%sGLu7X4<Z(ZRu&xxaXoQRr*BFY<)xCDn+z&x%gwzBdY$FSJD|EV5NMmSX}ZxV-ALWb<@^CL-'
    '%RD`Yd@*Uj3TzA~F<4l_1b448oa|;?k_77|%%Rg%1mL~hong-)>V$E)ok}2Hh7Z-'
    'CH4?^znnhW|Dv7SM&%vO63QV6jPk`B%m&Bl}c92HxBqU<!1=>7e-u~n)yiCMDZ{~*-'
    '{c21vW<s3vii)`zlvh|eY>!gd^Db_j(`DD>D#*mYhyL#zUiqx}p4?@-'
    'vcLX@4T#_<WF)La+$ULVK;_z>N*&2k6K5~c28i?CdCd=b&?33j<ej@3&8?J|>5T%WiizbV{p>ysr=)}@pKi_7?nznqEYV5xLSqEY'
    'j(Y<88#mg2d-Bt7>pa+n4{&i}!bx1;rdpX87M%-'
    'V+(nsA`!UTsHwo5u9_l|bk=q3j9H*XEb@a(D#4<UTL&WjovAuT>c$;bh_ds92wwHZe804ZrIreS3K?QG)$1F2g}by7M%0kg@^NPq'
    'iGr}WDs=OV^eSzfw|NDiywSgERUklnZyYvt2A6x3`c@+WXVJ2&a$B#y(!MgONa)42dn9#I-7Aau&-'
    '(T=@6fMmv$#qXEB(R%~A`B4{-E#ewZTP+>V;U3w(8r;_$YuS|1@(n-Q6b>s%FVx)+Pl$nWkF@v_@4tP$+8Oo9-'
    'dw|cw*=uyPI_MquS3HlJ++kBd;f2xsTVk!3PKE$C4FVQsL|7<w1+T61kqFf_kIbMk>J(*1urIm2h_3HCEwn2ET4h`bp+s!9@5>wg'
    'x;*K^P?pvTzW>x^h6;g6Js!Q)P^ZPC2UHt?Oc<DHvmJTYye`TWTS@XquOi=PM>oSIZ7pAo+t;%i<0!J-!$Y5Bj}-'
    '`y?`8efH756U)F1q(W5OCxbT?Z82o<gC0D)hqN8-6uZP3uzcs2C>X?;ZR8Wy8$a#dB0-'
    'lAeLPT#{Ze{}hIjQ0AIH|{ZhC`8yJ8UrBaO)Ei18*=WS6QLhO;qn<%uae&IsQer)KqrpCCj3R&#3#I9a4HZ)M8hN=woR9S`4uj{#'
    'f!cJ}%0{){^02h(dD4hzyw!UEnvjwqs!egKJat!_{~gc#737LOzIStmenhN*%*?8DD%?)fE2jTAY@jv&%|(>xU`cB@2`%W$_)k#9'
    '(ztO0kw9;6=%q^Mfz+#s{rXybXP7lK;1>%?M>1e6(uS<LAnuu%6gxLCfK1)EZp}U|v+meF$gMeE(2O&SZnX_p!*@vvKryD{9IAX0'
    '#)ccx%&b*(((BvG;z!R=B=dfw(~3Ia1njYx9pVb8jJmELz~ko253O3<z?Reix=~=~oHQ%DJ+9CuH@ik1E+5LK?<+kA(JQ#L;y@)6'
    'UyHN%+B?!%m%UZQ&qBBzBtR(GH%3@fUI+Yp#XRygO_`lpnV$U}0{P=XJ6zLR(*{`yarTPOdEJ+>M;4pyl#xR6DFD6Q@3ft2qvw;P'
    '`QRyw(xdJjp&4`JQcUyNGqynC`T^Lw;HiQ1|dAE)#Ehc<|dCxKQrWNasbvei`hJ@g}MJ5@UF9l}eD#lH)!uzlaWMEka8j_IJ&rJe'
    'Cm5+=FK7XyDR8rT&*(oXZ3Uo6P=@6bjQzDHiFgOK~S({rvT7rp!WnctwsoA3G`s=853nwOIw}-'
    'O`6jnzvpx77Xi6t_07iP*noowvm;?2Ie)EYpFH}V<wb01(6=q9xq>&9uI8L%Y^^{$Kqw@X!yD|82nwNcXx7dXX3UO3F}cG_?5}@{'
    'K~mp)*i9<V^A3!PA_bu{C6uq8wy9Z?tI%0!#XAsAp~lk-'
    '<euWa`JL#Zs(~dMNW8X+lrLya0eCx2SW0@AoL0QV}(3l<AuG4C<fie5WdOiPB3J_)8uI{&Yy3?GDTK!?4;S-'
    'VfLIkwxe0_Y8b(W*cW46liB;_Q<(?yHESc$Pqy+fTY?f3ttKxRi~wL}Oa}PLBoa0C{jXTQ@uCcCSd(W930G|PRY4iFEe9oQYY%MR'
    '=^FvHQL+w-jGnj<`o(&mb}36{l9G45*jq+E4oY`DeBMT>J29dhIM6&-#Fos-'
    'j;|etNGppd1mu(5v!wIN{b~cq^+%&VwXwZ21k83SqC59>NHPcUhtQq_X#?B7#RAR13nv99KRil+@nH?<yp!1xPx<0u3jhHPc&W`i'
    'A~R<`KV{D5^B{Z_sqcQ(eY#3Nv5L%)EcsG?97j;#n$sf3zbf~x*kTzsWtQ?6H3@F~=6M=eXiK8qnjoCNAas@MS{+X7RD&yx4LF_('
    'e}lDX)0lbKK_JgkIcHbws+5*Q-'
    '9V;Q=P3nQ;T>m4r<F5)F3+yS2yVa8WB71lqlmiuI{8L~G^{r}9cm>UfPC{`e<xM9i`WWG0OezAetl7i)9T4`$8VBQ2CiyT5U@QP('
    '~m5kD0t;@se;eO>w_7tUEpN<TUTv#t~ENMX>!=)Ya?`CIBt3xt1*2)FYySQ^PE{%oy=1Mh43g7zo#uy05Ci8QwRi*d;WDo(Bx?h4'
    '@(meb`wpCNvwFvQrAg({9Xr!yZN73?TMo&A_bs4So)SdiTTXFl=}aX4=!1`S&NO?DNY%-'
    'f`5=6Z>h17D?AnMrU7Y<dj>4~9QRvJTx{Xs=~SE;If{B8F@`1hXh7m)J~Kf4s7#wdoki*?iq&pXrR|Wdw~fJ}NWK2Bjcx%s;ekT^'
    'i~G;g3KWc*8zg<`<dDF(kKw3mVSxL@E@~(RetN<eX|Y~bDD^I}nb{WoY`>3KQZgQ5Ny7wx)5uDM&xt+_Z*~(kVq_HUDN-'
    '6`1DRO;eLXWi*}%AXOHStClIo1~5~~y+T9Z^mTx@F46R#yAiH8GhwNJl2Qz)``s4O8tsJa0)mN#eyWx8eFXjaDgn=Bz#MR6t9(rV'
    'A;P)s6C<%YYC=76km>w16sC!OBeCBsf%(^X3SPw`mZi0$4FmTxrQTzScR;QE5C=rq`fVA%I5qlbE6rv0&7>xF(8U_}`8qY{4gM59'
    '(XG?6KUbhG!vH|AegoEhRf;h`N-o2`~`0jlqfz_a31{E3gGHF$8&H(vwcSqrW;l_hz;2dtb{UV7CN>^IZ=f99*%-'
    '2&d})^oHM9Rwyu+(h+KlY-p9NyFI2yU%xKNG8)*4NfhdV-re;c&O34_5)|7NvwbSJ_1Bu%tI%j%r;?5e>ZKN)aDY>wLKnEDNGb<N'
    'A>RU0#Mhv?s;yylK99HSQw+S&Jw%_ujVb)$ey_ME{~b(F4JfXQXWTalYq%>T=u`ad!cLOyq8n;k?0~s3B1|A1EnGTUT!LQg1APF?'
    'IzPzxJxN{w3{wTCPCv}dFJSwxYtrM2}HtDw^ijXo`Kp$$!~hNFuudle-^1Iz%Is@_kV6A{?X5tJ(KhjOG$)}6xA-'
    '1q8*9$lUM|(;6a-<$$5x9$;I(R%TvNOH5ol^SLjq7ILsV1wi(U{kkN3loEx=#WRcmrg^R#&tN{IVY8>-Y-'
    '=SF|K>8lK=2M>cEltk;F$7w;Z#y;^D24`cm^PFbg}SDKHdTJt6ts<A2SdI9u3eUcmNp;vrG)VWJ^2)BW|N5djU2=7``B!t_AxKrz'
    '!8%omDV-a(P@{c;fnE_cg7s#^r-x02{p=5`zs=_KAhf%y<N08n5D}n($AND+kgCsoh6qGzF?fH#}TJ_&G!DO;C_|5=u<r|3-'
    '=|L`q~`nt-MLBy}VXeX@?}#mGQ7IWDK;>PFhVopc_42l?qZ}x?tl=I&hnwhU|U{W13MooWQ(fmC*>DbFVQc7)$kXEB`uU=qwSxRb'
    'm%kObWB3d%p_b9Mj68<k<dHv}JS|q&6u)(dpZK&%)W?h%9U#RzD`liB%mpz613t{cTK_<I$qwd0Db%2V(W-'
    'FWg#2&G3qlL!~?!2WCEomvPv3=lDpy>r>)_#^2zjJj{?zms4sbk;8zhXp$4xj)D&!9)lb>dFt*=fG_BwB|6<-'
    'T&oh@d*q7X1Ve|;*#L8numnc-'
    's?qF@#;i~%5FKN=>q(1`+>W;Hp>`XRcIv3{sh)L%_k%L08c6Bi|JgXTgl;wgd$fN`;B{X0Qz64tV%g}_6|a4wbKvsFwI}>%eS*qk'
    'DCMkn(r>#})2RbfQo3yk6SzVQ4HUfZrA#QF)8hdd-At7FTL;T%#qiBvc=3xs#TQ%NH`N}@;S!xKrhX;HhDt<8`1RF<La@!NBZm*{'
    'HW266da;OP?tDf}lteuTzJ>zG<SqbG>$7<a>eX4BJtNU#Rdg218tHQ28bZvsl49xNfwR;K1G4CoX_}#WTN~sLN!8_iRXSJi(d%mB'
    'SNNu?3a{1di|TXVf(s+{^|PYaATzi30y3MN+4JWEy%@wJts1LuaD(iK)gLnA&93DEJ;mBmKUeiLwsi7)UN}$<;J4j<$o1t`_?ejZ'
    'T=V&3ivOS&o36OH+tS4moi0*&8d@lAfoyH&)(9SDDv_SO(HBU*l{WW`i0$DbpI1vSewXIJRz56MfQYCEA|n=|;#TuM_Ebd5AuXvA'
    '@6x14dlC^0E*D)^*#VFtE+nOIUB#GUYwAExjJ5LL3)9=AD)8C54}Xy9N!;y9=mJv01!SDoHyDaIJu~aY-'
    '@GL=&ovgQePiLP#^!n>k~s*iAIVCj8$7TG+ao0Z=DpJS5;Q;10;JBRvShyu8-'
    '!}?gXp1)XYJO2<wD!p5{oSSyuNGg0cNU++BdKu3>)|8zI*?bs!v@B<Lc`-'
    'SSi7c^CsdBTf>_tn|tTD2c2%H6hbn{^nlmF`>!ovx|b8|@=cp&WvMOnTBjl%Tto?8lr{Lth&>}_Yn@WrqtKpMlmB%2L=$vglMo}f'
    'jEz95+D$Rn3+i2vuJfX7I^BQC7}LIOPYSh(@>jNeFmj!#-'
    'j@RRfOiR9F_qVTzjooyNTx=ZZsSaU0DK^G0d!H^vF*&1V$f9oBl8e9dX7z_8Xh*^Jt<<x*t9qcGkhAF%`-(LcseY#w-'
    'E=J29FJBI8(1Z=yM}Mw3w>C2(^z*!Hwx<c8Fm4rIqyFcKd>Zm+I+Y`E%pZh4mK=!D8WJR!0Cri=h2hnX^+hX{p6%PaIvlr|}9NM^'
    'U~dV4LSBN=4<39Jcd_$!?L#i`MvYW#<3%pOl(7R(H@{His}H&V~lLwoc_DY>P+P%yfa}*xKT|e+F5v&;9q!d!z>rKlEL3M<E?ngv'
    'zmlIBgRGo#EcP*C_FlW#6xoWvmM%zBvIYs&Tc+V6CV{a4$+#-2K6>w9^_GsQLf;Q^^-'
    '%``;%A9}wYow4^c(&Zr~P>703EX;1f1gWpE}4p3|kGKCeknGQmT4Xp{mp^`|nbr&zYnb+_z@mZL?(p(I-'
    'hg3@^*X(sMZ>`77jqp9!pgK?3nm?vYW8kPLR}ssR^|VsP3RgC#(qXtb*F%oE%l?eac>v;}KRFG(uFc_(*^bCsFgwE?Ow+8)i8fRm'
    'KF4^Papj6(HRq@7cMg737q9MiyN;SfWFk>($Y4h`wH$C{o!rm^M|p#k*O#Ay#UM<=1O-qg4-'
    'Qo!<()AEq%l^2dkzUpHIaZ2TBhnb4vO9rTiG|<jU@jyvj)(o<kPWrlXe9DRrg&hgsP{FpS!UlNo|V;`HWjQIqpHcjNTI&?*bZ=*i'
    'Z}%n=5WiMFeceE9L5eAI@JOgG%c+48a2`@K2+>cm_aaTfR3xdo|>0EN}|xyV29(#B5dqN2rw-'
    '+KCtu)H=`mKS;B{<Kxdn`r(9pw!}b~4*U}Z4zKBcyd8v}h36p4o6Z1>a_H3{v2<4PW*L=+KC=WE)je_){ewCtuY{S<s|dl;6dc<3'
    '^i8FyYPix_%qr;<eTFxAviMdY#yJrB{4;%1jokv=4&sk49EdHzDWM?vprOK9h>cL?wh-'
    'F!v0=RKgrz6uR3m_iKQypL&u+OG=e2IZt_GKolVV>j(JV*Ce-N}ds#beV+Tjv;xe{d+CM+PH9qSuggDC_jRlm+7ahr5+=ol%!-'
    '72|JzRv`~Tv`V;kVPZ5_|pDmZZaaUCvRG-'
    '2YrJCpB`|!4!o3QdvJd{1XV)ZZVZa`buJok*at3^h_79gLace&G2YDhhW1|BhD+oW&8G0x+NeJLqeV=Ay7Le(e;9;Yk+D?R%ro^m'
    '-E+XXMG|84peqyBk6^T?2l)}Taz`#btYx(Q_bt9zP@(O%j<s4}<kyW~>}IXuR!qTYQ7<JbxX*v_^wT4}ER2F8(X9}Q7T=UFK^nND'
    'WPs6Tc)+^Hvx%|4kMbwxFV|c$DiWt7%NZZ&8=r<wv}q35pukDO-Nx(S&IID3gh_DMi_EI!y@0zXb9GrbKi%>spXp5~;J`_ZZc}@3'
    '5@*xRB_x-=eor3B50rBPhtFFZC!~)7*b~#O<rWcp`rL!LOG?0WMp^dj=F-NCkCl2wDw3ANYi_npad|5Y-'
    'EEbbx*TGF{Ahx;6v84;Mmm6Tw+l@OTceH1@pB{sv>tS$;=3CH!l+QNa7@w4^4AFJinp*NoLp-'
    '|5*h2fD^Y^~nNGcC$<eq=`w@HV+T?^k7g_#Q>jm6xKW+^dl4u+#Afbt^_{>(Gq1o$J2kNXiAij%xy-9qsuN32n)`jv@JG%tccKn-'
    'G6;Ae=K)<AQQR3I=2<Voh^@rTB4iO#eeoa}+M=t1+f5bC~K2sk6?*ny9iWRVD^+Bao%te7uZXDeCK8$EE8?{Q3gS!$C`<H3Qv#;*'
    'ODN+>ab`DW>xUE>0UE}F!LGD|>)62vqP_Spe&i`)(8yy@e5^TV!0PS!1_wm#rl`-'
    'SLH2u$eJuf4WSxk3+MlHomz*%OoFQ5q{l6v$75PN9W2h?l6Ce};0b&gruLGSs;%hP;papbW`2HtNWIqruTz<^5jpX^wikIG!KTaC'
    ';sijrh?q!Lq@O8)v^MQ>dN)M{0No38w=+iYr`YNk+-#aA7(5;0?`VV>1^u7rmMx|MO|HU?2~&TVmnE}gI-QU?tq^Q3aMgXT04Wje'
    'D75s)apGWlAkLgbt*+2_3b5$ULPuUQv;vWdmC0G}5kEFnABV!{Zg$Nuchl>L61K(3^}7WLz6aIio4pkYY++;%Hs7uL6WOwI0rA>F'
    'oGw<T;3lO8R8EEybnB+7+gy-kG-)R3?3SQ)LXHYf9qRhukY52=Y1qJp7q;-'
    'Tk6TTg8nyV``TXvvSkHPOAe{u?gXIuv^JhdmM?uKsv)S^hi7tDC}RapCCtu!WsZK_#UBs-'
    'p>UkstY&hGum00JNc{Yg76jpnU6Q^lTW##3qZsHxzt)+wqek9c({^fCZ(buD`@S?vJL6RvNQn5p!Xqvd+!redo<3_$@B47fmIu+~'
    'tD@rAdE+`QyY;>O|8R*knyZn}{-23jR6{-'
    '(RdyPGfDVHk4T8NJsRIJ43N|UsIwdKWhOZulUlD@B{VV4w1=W{48`?NS4q*eEN5(f&L8ELEX<zKgv0fw#2NJ*O-'
    'eZ(AJ)6?)+s`F$WPnoMIs^;-WL|4QuWK<nQl(W1e9;!5EtYzm};xukH%^IN|pNIk%}FsCRz@EYWMVw-C)hJsK-^nE>C6if@ys-pv'
    'XcAP0@~CbU1V5c~9xx!{+=DbMLR{&Pnh)Z^t%ibZf&k|n<zxC^Hesz7*~jqVAn7lQ<>a}4J{;P|KnDi`4Esua5|^zrSCpD;jGnay'
    '01BF5M|ksM~3Dv&>16e@((_GA<vFN@<iUR<I{NZmis!K@Dxh*1{RwFK|AD}~u>^4;6*42n|yGK&;%mgv6j7D<(t?$<~;y}Y`qWN&'
    'p-'
    '=U213owZT%muEgResj^YLPb%6$HT~Va*RKu)OE^+)WJ<HhCg~xbuz0$eh6+OK@iTH=wC0xl2`nk^)Fl$=qf7&@yQl+3+z@piSz7w'
    '2u>-5l_hpn&J!&tD}0pKKc6obkMHS{EF7ffPg#Cqd`=E_SM{vs0D$R^J_yw$^d-$B^CZAw?h1SMH$!IN0X-'
    '<D3pc)@C5>y}t&nDL#QkK%FT3C}#-'
    '?h$zcORWXd|0*2^(acf+AB)*vqNPGyHYyoryn$jn|nzdA;Gv{3#+JbL}U=5e#Fxpa|UN9q}MRKYA;{CLAEEPZr@8XYibJ5muZ`$s'
    'hoSkQW9%oNJv03Dme;&5fN#3ES0KUUebtichfVVq;l=kw75ueUdE*l_v<b;)PyV@`~c(st(wsnDaGZKYX9UVxl=Flly)10Je9k?4'
    '4TefmkT}7nNmc77zR2U*PF$C_5K=1;Z{Sbu}{_Y4=s$C;!B0RB2Yx(^Jg@&tXhn7TE$FXvu%LnLtcs4cU?6f#!R4Sr(Y*-'
    '<>8WkYFBov*r&+TfYIInLy$MJ0xr=R5&ze<~}rIJSim!B>UT@Q@6I&xgzZb`2v&x6<@wPOoN;a(5=dt?MpwFZckvohI!;I$`sy<P'
    'E2vCHKvqyu12R&=c5s~^Dg6$K0fAIU0Jznza3U4Ei#gCf@%>_u$RcezuLN3>8CR-'
    'm~W?BlIcv$CG7@<;qrFLE?B*mgp27XvVwJ0O}>*rKch{Psd-3Z_DlIuyXUxnHF!%4%%@GQ@FB{4-us#`E=-'
    'Y`6Fco1h60Q)0UL<7XU&~Y^Q7?Gj7`BzE;$L^yO`rQSu12S57(O7VDKf`{4wCSaN#Jhca0uEvr|I!>=!$K!#QL{vf0q>f}d`Eq|s'
    '1Kxlp{H!ax36LTtf%y+b8F8!*g2T?f)5F1Dk3pXZQP=AUh^2fpS=clWhG?{~(j^&bs^7Hxha@r+Wu*t}hS9>B32+@W#QxQ0AN339'
    't+))t%Xfj+^widy1bUBVxIo0AM@g+3ctTapR{K#2SwlZr?O{@o<s-v6j-k9Caikn}wdQKke@I6$CB|Ih9m$_Q=1d;eKq!e$W-'
    '2n7LOVZ?#<;;el)00i;Bcyrodd{js#ayKdWVvQUi5t;XYd_f82H>+wMV0S{*)Dp7#dQ@-A=s7tQ;0dN_T#v@~V-Z7Wx$-'
    'L`#<^x1&VEIcie4vv$-'
    '*PzZ+iOIhoVU>NE*xbXR93N!;e;9z;|M(k9sq&eQ(BL2rtrx#WxVfGL6r6nN6k(>(&RM+c0*#AnZvt#q&=tS?k@{JeT)Hv22ew1g'
    'Z9iuD|y(xeTa~CSRrJOiTf;K<0pzq7T=V=pY&I$;@8O01Q2`_a3eAHM!$R#6t<gMnFe@tE8b?VElL|wz7I0V!ccf110k80uC<MYR'
    'yF+F7#qd=atwqVE4$8)&r|NC~WRQL>}RIYYU)C<374W)(V*Kn+~r%L0#xK>6@8EsL{_65%(+eruehlg{f)XosGuL$6>Y_wObTVki'
    'w{hZb8oKhRawbwknKk$Y`hd8P{9m*;nl%^e#>OV^B??Yasshlp<fI3_tRk<RBM|#g>MolLGde%4Kf%y5Y95uZ#?F`VUeCEX;sNS3'
    'JJ4_U(x+!UJz)ScwFjW9wm9ynoz0#5pY?L9dxIbi;xN+p!1n3AWpu-a`>~wsavDDx<Gj6)NtQ@Y}-'
    'AjpO5$`sekbmv%H3X4Oq`^XTpD5$%MeRSl0v#L5lqZ%HK$XZBIV7T_6ZoRFHbdq`*`wp<L+RiiA<Ju)=(4?CToY~DEAHNaVguCWJ'
    ')9m@Tk*P*8665%;ocK+w+2!4GTzQ;%%S;J7mOvQq~8g1QzkNvps74o-'
    'o1$L|@z%KVWiSA>=aMws|j?e1}phDsIM~8XCn3wt_G@x>hPHN*@ysy*5-@?a4#Xg;RONxK+h0bs<XKG6Ra+S1Ui3|#+GVpSR-jv;'
    '_LrwMWc5AAuW>%Vr8Q2EVWI1hIrj7Inu&(g^@*Zg~%RR|8L+;I(^Y1HW#^OE*n8SJz3eG<}4{9%OR>fEHF2RT_NRH7wCpjZ7B+1r'
    '})sI?lC`1YY96VJ>t9E1k876OUO^BrxbiSD8*X;waJ=^%Gv6Np?GBmv*Je96Uq>Jf-BH%{qU%5Ys(7Sm@GHT|o@kKzXI31Us#R^|'
    'Xq10GL9K`(y1379Pbzw{?euilzK0!@9qBUqpyXygkkuw59^0Naz*8P%=2&<BjfE+9)&wPJbYl55uEGs~M6t7Sa$l}v*&)kZGO2rf'
    'C${QfrEmXKz?H*3KLl(#^Ufl@UAU|4BC^}3g?0F2a$r_EECQHLKVfaqXQHEt8O9_&aU`qKLT`=cdwluIHMn-SDvjgod(L$gx0JUD'
    'KQ`2UdP9!fQPuOOEVf%zSq7n`Nx=VZdnrS0(f;Bw#uY|o8GX5EY4Va_G3M#QOY~6CU{@AvS&1Vd;1Qd*6_zdB(rcT;az*Bkck-'
    '4MktZYa%=uT)2AxAL=fJs>&v-~tT1P#VVT%-'
    'XK16hKM4$i!I)vMB++A46Anue{(a10#>4%O<?AY<~%zd*L7H3$9R4O$aOfDp1OGRErLEOb5ffTV_A7<9`vkO=MJqf<txp)+uBUct'
    'yBxX|_4PSmVn*;rMR0Dtj;qA?{YWZ$SD31`l!_3F83^fB`M{_7ZI)~QSgo$>2@U?JH(%y)T?dLw7q2Kf8^tPMt95zTo!%F6ONm5K'
    'IK)@5^x{%R0c?HG}PAHkQC=O>{!2OMME5sW37ViA=X{FbqzP1;xUf=P!cVL!0mCi1~jUe7oU&+^zXt#RydUK^MfzrpW;xu$K87#k'
    'cXxneQ=r9XjI4oz~ReBHo>jMyS!0ckijK5f!naJsr#qVqZ=?cS!aFLJDXvwJ#eC!6*#5419V9^obGu;y=2$t5n!mc10MVsw|gp<%'
    'c&NIqfJ{}rF{>wEf;A8&z1Mc_;u5>bUC-EH-evnt0+NvXzA_X$UvNlhklF=NO{5f$AmAsEHTCTQuwFjjwqpZYC=N{@>g57+8WzCC'
    '8y=LMVNtsQn*1LMVDXWMd(dfydg+N&Eg)VmYV(7MKgbtoFG^gmp(#~#_o!b8Pd^R@tm$s6%+GbyyMmTG^Unh3pl7jO$i+QWjtIPS'
    'ET$5OluH+U;+5K}_5_|-I$A;8bz!x`QyK<5=>hp)PuWB=?V-'
    '4u<E4xDW5(`mk!JxJH!0_?)B2OsMWS0fA3$$#~820={fWl~zJrj0$;I)J<K?>+Aa=z_d4!dk$R1<Z1_eNZLm(7ZGwa7m#8*@1`Ta'
    ';pmb9S0$NP{l@hc#GA@JAwRyIvzx{+|@QT&u%uZna5<VRps~y%{FIpC4+f4aHMAmw@>CRFWSndfaT_i<zW^R@5v<JvRTiyKZ5Umu'
    's@GlgzhR^RU_T!wc8q&?GQn_JHk&<EU+0qUh`INZdBdX`H%!p1U2dzG8D-'
    '(Jx2RAbWy0ckr$6iM#s~u&h?Kq=A!EYP_Reaor^r$2&H-'
    'CAdg7XMyv4^M3c{BL=4ef8nSKszBe}W(ofJgMmlVIPyxsjQx@k!FYo{tVd32}t+Whwc~G^G{Vxxn^wiV=EaH2UY{;NZu|f4L<cOc'
    '~1@c+u@0qe2wf*|bK+c7xuAr39?7dnc!no^X@8v2u&kkrVs>gNy@@jgI6(9amh})>GMK?8Hd62=uG?eiQZ{~io0yNWB!R7rEo*F)'
    'VailMeAVq9hOKIv3H59i<OIVz8&SgK2;E=arpECfEz-aq+`d6M-q(UsfuxeHcHoG*dbJGfdwyMo)3JcgR`U1-'
    '=qz5zj3@*JW<@zw?rHu0r8)GChdN_u?UfWcb5k6!L8|7Ga@EmtF42?qDkDJzWdRI`fO@~Ih-cr89BY&TYDZ>|2PK`K&bl{g&0sst'
    't@Hy?*J=a~I2P-'
    'W!5VFrVqn%yt+UQoZsEuPuAY~wvxCG}~cSEhHmq??Q{LicUPWN@N=MtyZ(+^|}69PsfpQ{Ylrk0e5pCbWga0=esY%(urLI<>rz(c'
    'FIBPOU_NmcRfF7fP{bD$tA_<B$-nsdG1V?Mi_uawNTZY#Cu@8CL2J*7C+U1Q~w#x~=>#5liA!mvoQ1yJ04AzdI-'
    '+OEf>Vx`r`!=?@_22f=Y#K!Yz(>5&Mz`iiR8bLi~UlpV?!sUmQY);+KhORoX38ZzdKvZv?5+0L<SapB3Hk_h$FV=)QR_ZXb&EXk-'
    'iRrIqW1YA*J)`6*GPL_`LKDZ%tq@%2(5Kxb{uA~qU(>WBs^o=ouLSdXGl5pvV2IIg!Z3NhQSh)n*4)q%G!9i)2qG!2a6s|G8)e;Q'
    '$GPoAfp&NeNK^iyE9)UPj{G#u4+>bc1vS;+V~=`L<S$<dF+SW8wgP<1QNVRM(h>~O-'
    '8@G>89Ogl|2HuB0js3zc%UWd`nT>6IoDkGhH9g|o%aY^w&jBxd4Z=PeQrA^G8LIE-riP3m99H*t&Vi4(yS2l0a7tbgLaa5`I`uMh'
    '4kEgFy}<sj%Bz_S!;i|%k(VcVcTutWcc}6^xvINyo$Dx<2XNb84Vaz3qWRJN5zI?<L$Xud_5Dx?HgfjQY&tuqbf#GR>{L8_@Ve52'
    '7)#&*<f9>ACQfLjwZD3%=7f!N<sH=HOFONj*)>EogUODI(*P6bWmh^0kvoeQTn?_V20`@^T!d6QOMV>MtqWebXm>I3!uvlK8@FbY'
    'Lq1azX>$q`#owpJ@vQNhM#f<RQ=rZQ}6>2%Yq(?vBjM5(&bQ0m*i)r#(hWa*sKP2G#S`N=z}T$P$~N_1bVVB-'
    '*LMY1qIZ!<@d2V=>R5){a&<~m<~r1O(+bBh9#h*d&ryTdYp?GkX5Jn_f!-'
    'UPBSUgb5IIn{!qu=NEzFmD)vml<|zI9J=*pa`>a}^cUFTIaxg(pSmZi>@``>pUUbv4EYm4ak*=ztmyvgwKpJu;#{DIZno<W(#L$*'
    'KBi}?*BoRf_$|DR}rz_DFz{QposD+7^K(eGmDPrRD<g?YKVLh!DJHbwbe#R!C{%8-(w9Z^gO-l_y%CA_bVl_a7BJTt<vs_=K*p}w'
    '#>Rt$1Zv_Hc_N!RxgfYhegw|Z+G;dbo*yrkZQtv5Z<YmLdqVxMN48Os0j5%oJED2L>EbIfAyD=1H!~+-;&sI-F+z-'
    ';dI8>QoQY&d_m^SqVq`rSNesM)!?eIJtKxn<F4jnf~InVl~-'
    'KrRfkrTZ~g&4SbV~2CKQr7)e_UcIYz<DI9YsZUydZffkMD`1G%Aa2qc98cac<$Uomxin4seD9j5dIc`RW`A9Y9CWTq@UIj&5HZWm'
    'GWmOj_1QOlZHBqw8ur1Fr`F~|G}A&)(g-1m^-'
    'DYodIjdusmX%8zdLW(n>dLQ)a=9^IeobWYrnAS}=DJbWPg#L=YDrKx2#2{enpz7IHhkVZ<tSNroetKN%*M!InnqD!R5lHcK)<$8N'
    'N!?_Ld6CR#;jNc1G7V*O(Q7hGbS8nEB^8*HW1!Z{l(y_%j^7~W>)T4lCiNw5>fT_#*|ZuZKLP5D*ba*>-'
    '0o@)@w9s`gN!Bxc}w$HWmG&L<|ByGad_QjR+a{kdI4)-rhC-{5bo1fFt)i*B}(E<_v2Eh9&-*DD-pR!Y_2o(mXxidsxJpiEhy<Uh'
    'aTk@Qilud3XxDry6%1{5tcc0(D*-'
    'WrX@j*lMiD1>MQWngQ^%f&+Ahi(M&8Y#5BbCThb3T*@f>HdC8HuF7FmT%hWCc~NVx1nHvVNT2o(=gYl=}4hQ1>Sq7&EubBWW(RXS'
    'cZF6Ij@58Cw$Mt4fSAuyxXz2h=w}WD%JR>pV6$Z>AH8K4;}w&VZ_yK3^ij`!49b>9%4yut27cn*vi}iG$u0OQ~+1n9v&UKD}{|kl'
    '5qBzk>&Rz~wA^z|DY}pR@-uiNq6YR3RgaAUK944sOKu7#wC<s&B6K0{W7SPI%A)<DkkR{8RgQIHq3g0nh8wf>#`796r-'
    'OF}moJcpK8A`^u)Tc7BdsI!j(wAU(_-'
    '{4t00mlQS!A?<$L=UwvJ{w_$_a&QD5UGlXl`&}sCi$MT78J!Z>iN<k=n61+s1KM&FWeP7O^s)SqVB%Z4CfB5Ej~39{?eq+)V{R@_'
    'rdLv$tik#+TAJ^gRQIYr<IS9>3xVcz`71g<2twQs4hOC!f6`8F&Ovsp>Lm&{WA!v8;dN@27Gq>y4eyZNFP>!-'
    '03KCSxhm!!ju><dVuXEKQCn}>BCp8Dt`M!!2zhBx*wUc1Xf;4C&?*>~7IUkC9K7^ZCIloKh#lQ0mI<v#{R(q-'
    'g$W9mol*F`cK7m9PA8eLAOv`N<N?zx5~wZ+?1UDLs3R6YFC};f9R@BwctyFXz>1AC1E2uxb5nJnoP)Owm~Ax*YM!i<qJF+BE1%a+'
    'x*lc01-PQoG_RuWS%&FmQdo#!W!AT1?Fc|UIK<oO2hT`!nuRP<N#eum8%@p!1n!^Sr9Xe9qY|de-Ed=$)@Iy>O`Kbk@qo@88@dD$'
    'AnJ+zE8a3N_2mj+KAWc}o}|b?vN}=r<d5^p2yS|p3L@nm!-'
    ')P>>8`fmkRu6?2pXdQ02ujYqKAoVMM=^3i^x|q7$~VzE0w(}$V)K!Xm+R=t(5bvwJa1&%c|jxhbpf~BWwiXh+z%X)rH~auOQmDgf'
    '0cz%=a3FMCmpwg&0bw;&d`9-g7)S-d%W0)|-'
    'Y5a%Lz^R8z`b^Fx4WHg<bqV#7C`aS{KN_f$78zJf_ChK!;WlMWssBA%_H$5l2F%k2Og9#1|nx}hegMa~f(OkTIrIgPRMcEscdn)>'
    'Q^d*T)v9kR(p;M&nt`wJ9PrIzJRpjxWtF4>4Dw{R<R91#IzV;(D!QWPya?0o8X7Hj{XG}B5F$8e}@mfRjdL|2=sym{9eBhKpboQ|'
    '5Z#sa(6<<?UQmf=%;g^nni_nwDt<Z8JFg_lmgm*_9*m~Ce%vQaEJ3F^7p9@TF<*;LBT9DAo>H12}K2M~#fLKdABbFf=9C(KV&To<'
    '$pc&W$MP6(F3g9{Qz84&ldpb^)fwM8YawXW#_eg_W@8I7A#*0^xj-'
    '3ZF{g7^o8JfB|W|7jigKyM_R&?}GJs}eu+%}dS=HrSszB5*{5<ZdM=^41*aY7X=A#kF?c=(`{awP+r*b<OBA=L{)ePYM=yU{2y1s'
    '6P#ub*Kl(*9?M!fZQk!8nSw$zbqv?pQkPxoLTeWqW&*T+4}f)xA#Nzt#1D#-=~~?*h^OD{3%8~P?9#H&VkDVo!j-'
    '50Q!Uq^~4xFHD|$!`2~$Qr#=2Z&a?03WicA8CZ!YGuJLtxTH+Mn|EWOQFSUP%g{ZwDNoq6{oF0z!7*#`ecjh+Wsatr@3<_muHUL_'
    ')6mnZh(bPH_v3lbk*WV%JNK56f&zW!AgVM3E)JyihDp3k$aen;2HtjC$kpOXNFa3dOc~CYQE(j^L!o}ltWKk;TyH|eOeuN<oFBhQ'
    'QY3o?eaE<W{5R(fT&AKSjSS+oSRT9V5wto|yBhzItGaQ|7&aoOb&adByO3=|OY?7h;ExRd0=5x`S6?#MgR4}%T{dwNMb9m|6Gs51'
    '%>$3m=yG;dy8sbOs00HEd0kWB@0RR91-ge*q6c;-%0{{R300dcD'
)

class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pack=base64.b85decode(PACK_LZMA85)
        assert hashlib.sha256(pack).hexdigest()==PACK_SHA256
        cls.fixture_bytes=lzma.decompress(pack)

    def raw(self,name):
        f=FIXTURES[name]
        raw=type(self).fixture_bytes[f['offset']:f['offset']+f['bytes']]
        self.assertEqual(hashlib.sha256(raw).hexdigest(),f['sha256'])
        return raw

    def replay(self,name,mutate=None):
        f=FIXTURES[name];raw=self.raw(name)
        if mutate is not None:
            rows=[json.loads(line)for line in raw.splitlines()]
            mutate(rows)
            raw=b''.join((json.dumps(r,separators=(',',':'))+'\n').encode()for r in rows)
        with tempfile.TemporaryDirectory(prefix='w1-late-reader-')as directory:
            path=Path(directory)/'original.stdout';path.write_bytes(raw)
            return reader.read_late(path,expected_options=reader.options_from_args(f['args']))

    @staticmethod
    def first(rows,kind):return next(r for r in rows if r['kind']==kind)

    def reject(self,name,mutate):
        with self.assertRaises(ValueError):self.replay(name,mutate)

    def test_actual_native_fixtures(self):
        results={name:self.replay(name)for name in FIXTURES}
        self.assertEqual(results['p0']['attempts'],0)
        self.assertEqual(results['b0']['attempts'],0)
        self.assertEqual(results['deferred']['posthoc_miss_proofs'],6)
        self.assertEqual(results['eager']['opportunity_identities'],results['deferred']['opportunity_identities'])
        self.assertEqual(results['late']['late_attempts'],1)
        self.assertEqual(results['late']['full_winners_available_by_B'],0)

    def test_posthoc_cannot_mint_credit(self):
        self.reject('deferred',lambda rows:self.first(rows,'audit').update(posthoc_new_credit=1))

    def test_late_winner_cannot_be_backdated(self):
        self.reject('late',lambda rows:self.first(rows,'available').update(within_miner_budget=True))

    def test_miner_cannot_use_receiver_feedback(self):
        self.reject('deferred',lambda rows:self.first(rows,'attempt').update(node_or_verifier_called=True))

    def test_winner_must_have_original_complete_proof(self):
        def change(rows):
            row=next(r for r in rows if r['kind']=='attempt' and r['statement']['target_hit'])
            row['proof']=None
        self.reject('deferred',change)

    def test_loser_posthoc_bytes_replay_real_product(self):
        def change(rows):
            row=next(r for r in rows if r['kind']=='audit' and r['posthoc_proof']is not None)
            proof=row['posthoc_proof'];raw=bytearray.fromhex(proof['hex'])
            offset=4+2*4096*4;value=int.from_bytes(raw[offset:offset+4],'little')
            raw[offset:offset+4]=((value+1)%reader.p.work_oracle.Q).to_bytes(4,'little')
            proof['hex']=raw.hex();proof['sha256']=hashlib.sha256(raw).hexdigest()
        self.reject('deferred',change)

    def test_setup_reconstruction_is_not_original_miss_observation(self):
        self.reject('b0',lambda rows:self.first(rows,'setup-reconstruction').update(new_work_credit=1))

    def test_end_counts_are_recomputed(self):
        self.reject('p0',lambda rows:rows[-1].update(attempts=1))

    def test_bool_cannot_alias_integer_count(self):
        self.reject('p0',lambda rows:rows[-1].update(attempts=False))

    def test_unknown_record_field_rejected(self):
        self.reject('p0',lambda rows:rows[0].update(extra=True))

    def test_start_cannot_claim_a_later_phase(self):
        self.reject('p0',lambda rows:rows[0].update(phase='done'))

    def test_duplicate_opportunity_not_accepted(self):
        def change(rows):
            attempts=[r for r in rows if r['kind']=='attempt'];attempts[1]['statement']=copy.deepcopy(attempts[0]['statement'])
        self.reject('deferred',change)

    def test_complete_audit_required(self):
        def change(rows):
            row=self.first(rows,'audit');rows.remove(row)
            for i,r in enumerate(rows):r['sequence']=i
        self.reject('deferred',change)

    def test_canonical_option_bounds(self):
        for args in [['--max-attempts','0'],['--seed',str(1<<32)],['--mode','unknown'],['--seed','1','--seed','2'],['--seed','-1']]:
            with self.assertRaises(ValueError):reader.options_from_args(args)
        v=reader.options_from_args([]);v['seed']=True
        with self.assertRaises(ValueError):reader.validate_options(v)

    def test_frozen_plan_and_authority_denial(self):
        plan=json.loads((ROOT/'formal/pon-nakamoto-v1/experiments/w1_late_assembly_plan_v1.json').read_text())
        self.assertEqual(len(runner.validate_plan(plan)),14)
        plan['hardness_accepted']=True
        with self.assertRaises(ValueError):runner.validate_plan(plan)

if __name__=='__main__':unittest.main()
