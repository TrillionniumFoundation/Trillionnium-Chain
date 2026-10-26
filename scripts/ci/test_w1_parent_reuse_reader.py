#!/usr/bin/env python3
"""Real native fixture and adversarial evidence mutations; no performance test.

The compressed fixtures are exact pre-freeze functional stdout, not invented
success records. The source and executable hashes below identify their origin.
Every positive and mutant invocation uses the real scalar work oracle; no proof
or clock verdict is mocked. Fixture generation is not rerun by this test suite.
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

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
import w1_parent_reuse_reader as reader

NATIVE_FUNCTIONAL_ORIGIN = {'baseline_head': '33ff263a7dcf738aaade46ecd98d2ae122fc5789', 'source_status': 'pre-freeze functional only', 'binary_sha256': '176ee09e2f09f78a47524ebd09f541833e584a1261ffaa08392e45a8cadfc1ac', 'rust_source_sha256': {'trillionnium/crates/trnm-pon-node/examples/pon_w1_parent_reuse_research.rs': 'f47edb72c57d68efa6c6410cb2dab370a5ffc831e8e05404ec206975d6db8a04', 'trillionnium/crates/trnm-pon-node/examples/support/w1_parent_reuse.rs': '89100c66ef356de76ecf315a6de4ccbcb0cc1e27c4ffcd4ffd250c151d2ec863'}}
FIXTURES = {
    'tiny': {"sha256": '8f2da87e0e862d5e24a1585d97fe712a72df426e2066b13614b528c84b911450', "bytes": 2826089, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa761SMbT8$j|NrD|iCq9ah=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNJHk=S$q3$2CZQ)hi=z6Ys(a1Pd^;fv3mAUqo0tfE+df3rse{!sX>$Y&=S48i-mrYVfIX^7J(+u*k`w^a(Wboqe'
        'L0~1K*9c#$w`DYUrPisyoDvU|LDlIS9PGqeKl8a$3)H-)uOwh5I-8G5FfCp3#mn}re_yk{%?(Cm9#`68;myRgtG!BOZ^jsipB_qD'
        'F*clOTwNZfzT<VYIS~3%;{2A6yzb~M?)>Y|{dK^9ME9p!XNz_}tjXZjr3zpy(q|(c);>Omtn@bW6fbO~XN~a<>^n5-02j@f4o5|)'
        'h`yvl<i03!3e(VM%<JuuEREg4L9p^jLPW1>VWUuj!jt|L7L=UhyNyYEV9axhXVB)mX*0k~5f5n-9nd}WWxcUXhCHjBP){M2tGK0{'
        '%1zw3MOFOIn7_0ll4*N@o!m@}vZ&rdDNXu(;x=h2d}6H`UVh13RssYGZ;F%d4&W;LgbLO&tg>siL}1EWK1<uJ1ZKrn6mJv#EtsLz'
        't3kMvF5KjP7LlF+i6rKeShQ^_pUL-tGAYqo{&ab%IbmzA*DuC5anY}UmwX-&{@^eXz#ySumPhq;1`|o=EPW>BV(q+Yy%>^(5mJ=P'
        '%ohp$OOrDKifxNkfcQnkt;1!_!|nL`6+W(A#x9!n%}N(O`t3K?ZFhBuBy29jgax<4z(p38?$2yF&wDweO!-8xpYG=tMC|-ie*u~%'
        '&(Yy(P1R!;Vcf3zubDIdCz4H~g*9UDx0WBC_bzby+9(;?;k#7A4@1tlad=*h<#c8tVL80I%=x{=mC!OO!rk|i1At6sirt3ATvBK$'
        'AJoKaE^iFy7avCYtT3n(J#7v}wKIVo5ea@Zy=<KiJTWXlHK^^mx1(2MVnEAurwjkH={EIz!T{uReAK*ePA)n^#NSL(eapx{a9}y6'
        'iHspD^Nq7cE+*L?vF|P~DsOmO0<W<s^U(*{F|Kr*H|(R&{daWb_YXhtvG@0$l!rZvOq@B%P(x7#<tkWdpvb~+oFI3NaBeIU9@oCy'
        '*b*O%xY2UMa<f{U4|8`<B_$wF8O&7==be}AOwRa9q4iRQxM#*t50+DGw|cubA8<g~UvT5K-y7nYXI-5#P0)IdynB0A6pC$?OS1mx'
        'I;q4+x{Q2VEh26X?M&ysvCJYqtUUOO)y6La1)X+0k?iSf!>oSX5NO}7fdmSfFh$+?a&7eG3zP-h=_tk+%_&li;nb24VRZV`+6fit'
        '*asFNk+KC4DsL_on_=Q5R=ZxdlzQbQ^)T;u|Iq*%=bYouUQz5faJ2r$Wc>A#0CL|#4HcQia^{#WjZTVZ8%_6G>rZXs@gI>#t*XB*'
        '*r4^M^g(I-hXUf!4N8{eJ-7eBT#&zCOPx!Nm&e5ED0Txc=N`BiIKm(?y>dNv$qg8?MaYSfP(a;03EhZ2+E0P@(e?Nxf}>x*J8VSq'
        'a7jBDnsO4-lQ(7C{gUJPUrubf8A79klVNWmP&-8v-WvIGTG%0H8|c(~>L9`I$UZT$CD~8QXs7Sp=?#188gx&f)IMXy%sA{tbLK3B'
        'K2l(U7X1{VytYKNVY0r?C3yu_;^2@YrK(20BoNW)$gJ-c>aZHF=frW1-q6j-sJwM<sjtVwGY0Mi9^@6b7z<3pHzry(0CVC<!4{`W'
        'S?KKGXIu7@)U`IRg+D1}^G*PQ-aL;1ComF$S3N0G&UJ;|g`kN*_^4$^5L&xKgKL6jxz^SPl-$&G6(ZF7V~dgyEp}@)vrTI!4L8^Y'
        'D^xo=)mAhDge-BHUd4a>S^DCk@vBf0;SVvsC*9nWk}OyLk?QCABa<_`j2#-Q5N{mA?g6%6_(_DcFY=O>#}>PEwDi_eWG&k&C7M@h'
        '26C3*Ut`QnIo}t$HvDRiS-BWld_-8)@V>CIYAb8~gT@agr4MOcTr*e@8=<Na9M??~1JR4~gOSWA^jgjj6Oc4Ih2o6i63QUhw6e92'
        '+W!U!M=aCc2HL39isjW>Q^hiFbVIM&?q>@;&k|CFcf~}lW8Qf!dn_lEQD3xZj~-{Al=qxg3uOkDu~tt8aaq*Wq%J{-v!rfwkg%hR'
        'wmMvJuaFPc6GYzb<wYA~C3uDU4B{>2)=IIER)<zvj%Ur!Lnu+7#IWZhgvz(44wTFFOwOMqW0Gz!v!9KUIiG0iB8;r#SFM3=u4Sml'
        '1@SQNzOPTc8c38JOMq?Jo)vbODm+gWdqSGTssS|CUE#Wwl6dHGd(?{ib+l)&jIe+ZN5$=$v$wIR^H8=$>{0nH`+J6$P{sm;b3c39'
        'Z@<wWt`CCSmnS~^*TvH+6_}Ml1{}|X#IzjnJ;x9JkZH{Xnmu*RKphzrap3_?L*Z{NANqw`?#z;%_Gts2@8og~bMj$uwQi#4i6?y4'
        'IkvSnn-b3B2qMEd&FPj;YUepht0-Y?Ah-&5G2nJke2+BqbE=nSGsX?)=!=OWSZuwg_JKsGtv^H0-LEpQx!5RcORI_E>C>n@jkTlL'
        'NPcrWC0yki_55b9ZT%Ic5~br^?8l0jlD6GL373aE%sce_qF=<EXO#BwZz%|ab$quxlkcNRCmQG<;FnXrXNBPB#zo<XhR6mkPlp+n'
        'nNF;Y*KA&RqgZMxNfpHT<JhQK(-GOR1H(rKOoA@NyLLe)+dOX;8f`t*bb8AqV`J@B1$nB()l!ah?}=Svz+#IBs9_c+ae5fbvb$>5'
        'ZQ$Tm?f&hu(n|N!gaTVIucvBSt4g+8d8?`zoz7E40u%-dyTTww_}rP1rmy|s8t@!Xr+$LA%M1k{+8ICXPd66Bf16K?NAKW?#A!f<'
        '5Nm|GmuJO#ag&9feeT2DnyO}6UN<-1VM<pCX-z;>yae+knQ*<f4I;3#0t+Kxi0)KK_IX64#n2iGQpgvm{2wK3;yy$UwY{jWp5b+N'
        'c`Vz)(&AGd&hPwiL=pH7$aj=1_{^VvMib%+?_^)s-UqUCwNtVUfo%SWR;V7*F}XAORD_s<rCyPKig0n%(1O+*%H9qAy;W!-6#dCH'
        'C|wgh=ZIWpJ2+h$gu#GNym~cyj{bjZ(9f}MW}eh#NF9eq8)l>K1bE6DCQuf#&0x1I?6FY7e*(w@qJ#YcF1XNluP_r6(tO}(1~9g$'
        '^l@(vY&$Dp-u505h1)--1qju+K$`ZE*;FHEGL9O%Ng2gY-4(1(CamzCnOTP`?;5!I*)_5=UQvNB2d;3vI?`=<)_8ycTmHmb%EBT8'
        '&)zT>%t2oEcMZ@JyME0wL5X@3>{pnO(!Ot|?Gf`WJRr#>A``5!Hj*VPYfHmLD4K3nlJuPk4km5bzK8s!Idk9kPJpvblWfSOI!aEs'
        'PXG<CE(@)wx|f8$Shg0+-;DJoh?=vn&t5=lca7SCNGCU73!s^^HqC(aQG2Bq+z(CJS}fy`dMk7=#jjV(Q>m#nQ{9O6^k~rbO`Ks{'
        'Vs*<O%uy~glTk#eYn{W0lf<pOFye`bZT*IK%D2{~AJ0-o<rM(uO?>Y|qlS}F0x^Bxmak_D2q+Dg!#$LZ>f$E{d3R(TsP0#m!;hB~'
        'r!CS(@v2PHtvt${;NOp?hx~w@0JoKVc0kS~RwxjWPji*^4Z^qp43G8bhX0^cf?HSEjB;X(eHBT!r;7+bD=EDam%@sK$?w?|6>gmJ'
        'XuB<-qq0_jRIXN0qaG!Yy333}Pv7r~@2mS<x{_$MPL^pXe@ABZpFPw~A1W0<$367V*LiI21Xf)a0fzdrFT<zqOOAVG)F_<-j4}6}'
        '_lf4B2>AcRv|wXpW>9xmE$2u|(RqR+d65{N4wz?8A2vHy>;=(}Q+n*v)+&2%DFQQMYBRXT?p2GNOxUV{qEhD4r6Ts7*%??4(8%AU'
        'qJ{?E%;z}L5Wr$ov5k{fHJqc$w$r^44APa(&2(8xB22j1Z;W>|tQ0#1VMp`qFkctWFBHl5{|4VheL4DwQ)TKB>_)#Ia?2jvAQ#Iy'
        '$;KLAX82rWb0l?8x#Im(2P18AzmlH4RAiG(0jR85V0~adW(5g+NRz|51j}0-@&cdUP9jo$dOUg!Uq$-qcPV{du=&5U*6>_rtqz}p'
        '2GVqIGG5YB<g4K1a$$VmxsIyti^U9bq*`3ja^um5YG<-Wp*Lba#zvk+=SkeRL*Uc_`}T?vYl?784ANksSj6WajeU~>i8fAA+sOta'
        'Wd%PGf`N4a(pVg=ps)3@8+N?67bt=%mC<}xuHF09szGNs+!Gv40{x<J9K)byKruHz-GlWD<;J)9-iHe|QPbD^Ph>a20cNLYJt-Rv'
        '<g9VZqsblaSHe{`<{5`ZC6Uw0iPCa0TgJrKOwHIdF!B;rNj+^W`@WnjO^N={IJo)_nX&G=Rl@O(0)x`A=8%~FNaTTpzC085g)Dr2'
        '>#8>BP!QWGGjnzgLdPEJ1|{09OrV)a-5;)MXZS@wdL%`Eaebz@VBHX-e&g}`tCsoCQ9g`dlv2Rax$n*W#}h?3N4#gU*?!qu?Knx;'
        '9^%8SMo3+1;o>T^;jY7nWqoCkgSPYt*<Q1*7n*DKPIXmfgj*z!5ho02OCQTa+pSULIyLNjARth=wk;zT4m{7O(W5uN;C)52+)$>e'
        'Ho;;p+KdWf&}M^#<I<8O42dX@o@KNqCGq1(9W*f?1Ua@Q(m$=&Z2zGMe;)wrRH<AO2HbU7DaS6^gdkJ75xYu||J=$FF8kQx&GH%w'
        ';JJseXXR+tfBmA8OdZ*c_WyimRwWzN1Dr!sb)K|6f9pC=nCL#6!X1svD*L}F2rLx(B(3H^>ovHGzC?zFoZN?*b^BM&oBncS<~rK|'
        '<?3|}G^5X~>^%anm)zMWAdJ$M1)ZRu%5Yx9;SI@X$s5Qc9H?Y;X-lEAd~Bj!?5PFVz(dG?KVQ&B>e}Aa@<Qe(z0GjA<ZoW6wKkxY'
        'BE7>trgGn;B1X0M-RDf6H$;McB3<wqy+-Xt)MiTpOg>{#r^s{d@vF(oc7yG`q<$tAFeo(`R$LkWk!!Q>L|Z&oZ~Sb4+rE&2R{-wX'
        '0tm+Z$B!()9?(vmD){&x%1Parbi)#iHTI|oVv@9Sse<t};_ePQU!gN6-%1X*uquT+pm-IdHQ6ZfC;lZweP4guWU)iSO&vYG2Hykc'
        'eJ2<}#zgtWwb~_7R@DK%jiiZ1Ae>5ELK>b(s3qMq-hd8T&^POSXADikbHPb?&~kEH)VZ;mi`u=^OQnGv1k}`3MY11>^J7Wj#lveG'
        'so0P+4|CLEBAx-fJU=PM2XBI!W=lDuLN<d~kpjfM(8#;rfK{NMHuO7bI9#wZDWzEZh>OAGQS}g;l4y_t#NYU`Oq4AbS4u0s;Q)~J'
        'i!9}MqBRRs`GYxO%K!t3nNsGq_G0E9GJ^J%fk*kxY|=#E;kJ>5aO^UpRJyg#Mot_+Wp3}w-W~~>Ubk#x3&%{^acO|679}%%pCo61'
        'a;O{|I|EsxS<-#^ayNUBc2*!X!K9eu{(nFwW;M{Db-?rrsjwoK3aQR*hmgB&DSV$U&m5H4&E$FeX2EzWTDB3wFS)CmdHj?=(g2YR'
        'IKq@N&s_td8Bn;_St6i2uCtfzXErzW%#o7iCi-VsHzOdrOnlV8nwuX#GIKUpEs&Cq0N7MUF|Lu~<liWnzfBuULpEPC(pThCgLE={'
        'hBOwx0nKr&+JH0>T08f9dWQ@aMUvSe96Am_b^6o**<AT&<*|~O3-LD`{plkai?9RLrc2DPJADrr45MrQPaRrK(Qbrhn(ik=WNf?c'
        'A_fAPc)grb+6ID+Fb0Xhi||ck{En46?LbLKUle3V#L+XtCA8tAGg1V;6mA@Qm5LHi`yH+Dd8X>0L3j-O7U6t=+dgQbr0+<+m+G6b'
        '`bO36oSqtT{SJ5z&rtN1I_KJ?>T7HO!`RCuT2=5MX`Q=BIZpjUx=FXvo6l}`Mb)aWr+HN+u2YJA9LDX;-9ZV$^X(<hb9DWw@}yH+'
        'ph@fqM>2NGhnHx?5!aw7Ks&IXEEVR?wOP$4giFnO3;@q`c4ZxNW`>qT5KBxX7DJu8!ZIS&Q6><q#sC-7Jo%Hog<_;qPIn882TAMJ'
        'nJD7_teaMRkl~28+E;1u>otvI)G15A)3ZNa)MVx_6{pml+8k~xaT@v4514hUDMLhXzg9X2wGwzNJhUS@-K8sQJv+qQYa(#=OyW^>'
        'K6AO662@bQmF-Y8ecNk;@#a*a<N8sK9D&j7)QsdT8N6E4!$o+qT;|D<gQmKZx6vKH78HL5N!TeP7nRp4%SKp%`qxdi-DBZ7_zVJ-'
        'afHqvg*l{JoF|#3%OPLlIXXqC+Yud~EuQJt`vTA6!uYgl5^zJ$H$sO9E9B&3r5KUltl_{x33)IaZBr6sR|<5_PQO;(J!8d;N$9Ma'
        'qb<TJ?00$A_Uy%<iK6by;a^n-C|p#vI2OyueS&>vU=;fg(I!e)VJYi4RSCO7y6z}z?c*cKWwzG0)hN1J1I&L5#|t%!X)&o4MkpJ-'
        'PK};^#(LL<@65vvKA=4S(1FhxR=1vU);mEW68|JFlM=#JQ3n4=Ll(_lrG_}j8u9geDhonDqd1wtM=0y!tfNDtL@N)JWkqqtJmQ&B'
        'C4DP7k<TxY>JciinTm@6dS#Z`CsNcB3~SC*;W46WV*!|jMnn`dE)eaB&01JNkE-zuT`L_0JL1~p(TZi;hEMLQJ(Gwl^iZ_=_&Y+C'
        '_IndKh0{F$={+0h-n*X9!VH>^uw({bq=(|gYc=CMBRJ0;`e-g2-O>o}it5ii7kHfSke~z6R<b0-*=psLc#3qKTFhGg=EPFIblX`2'
        'G@Y~IPn}_7pTD*fH03@Vf1>Hye51I_0~THpt)Vqf_kn`{DS5IQja5$(Wx$!O1zDwXF)24#9Sx)9U+m#E`pxPiGv@BgqwZN01qk4('
        '2HlZOyfGnF7B%Jns0nxIq<*2o;l8NOaOb-;v1j^8Vy#Hl+sSJwV5~L++DQ-{y_(U63Xrc}LKhk-vDn@=!Y4}ezP)r-{#!Sko_Dt('
        '=+doG&|>~AHg+ruRhpv8KbF`cmep`Vbwt;0*cwIeZ<P9GgS5<+vd7}N*ed8Kb6XYBD^(RnaXcNlZD8g{%B4ktr8g6Jb`ntXnc*(c'
        'VVpBO5OwaRzADi}N~e5QgvN`%leYU*3g(gAE5p|9+*pwE;+>wAhvUBnYwmq+ip`Y2wn&pD8JbF;eOIml(vIg^$gun7Oo4q<5fq@('
        '9ouczYl<d(e4z;4_waB+Q>tOU_QY!|F(OFZZJ^`(c}2TG1kd+Zb~!i*;^uw8l^~y>G*qfqP?xO#{6;6lghXllhm9L0_mme^4{vt2'
        '7v38D%UA6OFZ)4c3%;><*k^^pi{Sm~a%HHP?}^}^BR41<RnR#<t9ItY%WL%r<bp)}__B2i-G~eFEmxS$kJECNpnA5_NMYo188P{j'
        '?4^nf=I>uGrP(`pC5rqVd^L~Y!xR^O3+9^nzbK0iC+P4nLX}9D4YtkSWk&TyLF@cwpQ~umlOX#W4^e1%T%v-U_f5k#{+NP|HuA=_'
        'r7Tp*u_LxH+-d;l^vzM1)l{Shs3@-!3B>4ygDq2h<-f!+1p8=yRNR37-4yCy4kOJ)ie?j)+)LXMB63~)(Rz(B?9hCE>+RLB>S69T'
        'A`l<9sv?c}*(smvo#9&62&VE6xE^<2&3=CEJ5M_z$YZ~2MJB%Kk1a83{j=XpKUPi$z&#fNjw0G}T;ka%Z<C43y;YT*`#=QAP26g2'
        'x2?$aL5|p2s(GMC1;!WQ721l7AB<Ste%P**gt%3=j(lO_Y0W+3#aVuVB>5AN*g40vOCEz2KeR=m`-2Tk8>N)>V=Tu;iYuZ(sWpt8'
        '8;0@{x9ouXgx%9bwEwXcUG*@TK%?4%6zK@H$DI{+)%^=_q<?yR%fwoW*(BXeaUk;KmG#s`%f>(keOVd%L5VqD>?qtnF`@$AU#5nb'
        'ANT8ZK$|r5U=uRwI(VPX1{JxFAE3|ET8oNv-W~>#b#+r9wH9)V6*Eo14-Ts^@1|7yaV|p_9wrs90R$8BR>s-T+>;vT5I+|zVbn_Q'
        '=z5Fe12G?q$Ne`6;3~9a>n(4c`T~%g{-R-CLLXMBTWqK`<@cKKFT@5coIv6YC)G!GLhtwH;Pf<LEpoa<w)>{KYobIoyXlwIP-si6'
        '6@A=j1R4mn4hvyM)GA|kh-5<ie0~7q9ucX*JVML?{+~SLY(mE(Gc$aWSob*11i;8C`E|$+B1_1vK^QUTn6L%Gnm=(42F12bU_)xg'
        '){VNRy*qXZUx0Fq!b<CExR>Md!?wJ>rjscy>z25(gNQ)Es}LwZQaMduGBY{Tuh?#wrk&{p%c6)>oIftdVBI@i<;6wveKq7@d#g!q'
        '()!et&YdFWqQm6V=%Q^MX$;ksQlR|CYE$7}+YOlTE`QNxjZ&3)I$4iMxh7R%#z><`cnA;~r++NZ)aKOtDJjbkF$3!psXn-t{Xd=9'
        '$$}6yc^c6|XMQT1Jrtnz5lb<mzG#x!S#6i|08vknlR_A5Bw!02(4<i(&}DEzH|Qkyh!E1WI-&k`m+*arW;%~x+o-dhF7$&sw!4AO'
        'aZ6@pywqjfPn8oCtVYtXHwPh73ox>_+tju|+<W@_VNqZLWVkO{3nVk%QQ9d0Tg<Iow+}`kCzAO*r0U>)Axot-OF!ADZ(cj9Qj>|<'
        'OuQn;A;pm6UK(6J<}{$xU9>^6vV*H}oN{5#J#ixHkPUW*6m~zemZrOYSjK#5rZJnIoEPUJie%V7No2?3sfdX176ca72#d=-QhlDE'
        'mr2U#a$i|wAuhz)0)QPYcm(njy)K)2U^F_(zn`SPXqXr~>!)(SN=rN(K75}!%&{S`>a^6*LzI030u6?<KzTp5*$?b-0`X=ZGw*--'
        '!-jr>z+4XBXM3cJ3)JH0S(u-zC!rM(4(bS#RVFN}0vR!fL>u_&C)fI=Oei58%TT+*h>C3@YE(?8t*&_UI_-H^G;ue4rvA^jyij%{'
        'vmhblEe=Kzw;7S`OG8faX0PNa69Lg-$fz)2BMoi9rg(YB82t-2oTq>V3=TrtyQLJ)B^Or*M+<pA+tqsRggVSGu1H3mGSf*ivtA1L'
        '*Pp30nSrbD`m(2~>lpkd9w#nM?-gE->YT^zY-;l3ndt-07i(X+TyVDK18jQopg@Q3U2iAp0s}#eGs00Qy4x%DhwJY|Rb7!yO<>)}'
        '6g^JUqR8{EwhbL{Jp|s3EWzz`f1O=yHe4RlAf57ouhGOJVx|Xp)+5@QWKGCc*o!<Mc}3&!TO;?JRyax?gwF!$Xk`sZy)Qi=N(U?F'
        '?G2QbTp_&bwM*ucoMLwhFF%<U2Lx^Q%eoO|{vWA`PvpcP^B#nkztM?+Y_?UOoYI+T9r{B;y>OVvkid^njf{H0-&Bf3=JFAuI`GH#'
        'iC7#!&y(-!k6gyDnus$&PIFBt?5wemO{g)}+sFt~p);Q?KOQgbiGd(Dm*-(8b*6pw3`v9oD+n;{dCOUi;Z<lLaLnBLHSSV_`m83$'
        'DxHah=KHIT!1E+5Tic5e=Vc&^DoXj5tTP2d8=ObF9x_Rbw`J!~__4qlt;-*@My+lsN^i{yc<H<M&cNbDpxGP;zU~|4f3+Z`<aKG4'
        'K?e+&Q`ob~yDZ`B&FSL<-oG$1&eP~FTkAFZZur_1y%H|5mk_|!`jbU?Gbx1=N2Idubj;vpzK-FF9r8-R4QbBqw%pBDL*{uI7<jvi'
        'tAY+r5sRipSEFpfLVM1h3v8;VAXfNwSFgf~<L);Yru=*BQ9GC3%p9{%_D==}-oLOrn<XaH&8AC+O)Fb(=<T#axb}&-U|~oeynu=i'
        'cVxtH72hw3*1pMi*tHBhm+vf*OF(yPVGE{ccgkqir7U=EzlFdNDZR&l9ZYK;^RN?+lZ}UL=SUJryVSArt{){ticGET)bJq;Vb-pu'
        'NCK7;Ge#_9?7}`>1e$34{Q7}@r6Mu=mCP{(0{YS#CI84l)?}IPe{OeXs#yHo7|J2loxPm-VbWtWxy(&RpOC9z*-k`sxA<c8zBbN|'
        '3i_v=z@+Bc1zh?+++GB<#NCroL$kf{W<wee){>Bui4}{~0Q#&uGrl+$Xn2<PRfL!t*ELj|P&VHGd+U$tu0bgX(z0^6g|I~gW@~AG'
        '?y=!>Zz0Z(0_gbh*r56jG|TZ*pw1J{0td)G9froETea=UZ|H6vq;=M9<1U1@bm*hdO`xDS_m@krjPX~jpOfwK*85?G)nUxX!;}w$'
        '%uN@fu4`M(S*6PlY=v+^Z_<sSN@>KFg_D;wZ5%Cn@r2nNQ7z-bd*Rsj!4Uq-DHs8{Te8G3z@c6xpLSf9yfg2#)14gk5Y}(rXXgC$'
        '&~s_-z3&+j7-0+~FrP4tK@jn;C+S8q<mHB{Q-Pw~7F%q%fx}$SE>f!cu?%_IkVVkAH&)n)T_sqXt*W4GKdJ{QKh~~*mPL_AQ1h$}'
        '*DHY)w8naIh8d_=X1KRV-cf*0UPw6GA36v648xn%v6E*}EqDFrGDc%{#+VoR|Jb**41b<&tXKvPA|<s?)TLf3F9om37nAE^N4}N4'
        '0A66FBM$!HvK~NP03ag>f!c1ym0|eK4PS0!tbVSYPvkNW==)j4m%K&qJzyj_g%#3SYxy(<in8aPV(%3N*nO3UJW}7LOyS$6_AZz5'
        'E&%gJVdrhd98mkU8UOvcSUgQ1Vnr8g0Zzexoq`$}LA>I88^s_9A}IVqKW;Hi;#n~3Bd=+<Bc1G>vH!)8-N@)Uh!HRJ?Wm!9*x9_2'
        '=)UmM6Czm+FWt`kZnj}o2VTO<g?yehTYg$Cf}F9R9URPC3J(GNTyqnqCyI+@&T5kiz9o{&k9`dvK9i3X*zCl$kBNrvmgWiw1`$qQ'
        'R7B;|T{xVa&S<Yc=uk@oC^_Jg<#x7g9&cSI2zRrGW1hM!vhvNdjt?QxPGAUIeUSGBv9k=W5y=IO4a6_8((@#<MVJISHI$lYO~!}J'
        'l8m5n%781pEaMZ^!0OUrQ@H^?M=C!Bcp`=sat-wENz&FeED7XuXh781g97AKPX|8WI}5MDjX0_s2^A%RWRn@(LRq6_uD?A87Pt=+'
        '65xgQ1|ic{V;RkO3<vm4c{~v@r01D36o!{y$JU3DV^YW<F>@U69)Wv{(3{2TWP&SLrNDKMv`@W$R*1{}3VaY%F^#Xoa57p<o5Gjn'
        'PnF+RQSozl(hP=1UutZ9N~LAVo$3t9+*}Vi0zQ_m%Yk4X{t$|}8v&=%y;H&*F?$%r{q=U>C5_oCExYJ6CTI%ak(}U}CtSdBDAD0x'
        'fjT2TG`;cw*Bphzpp0;%=0WLTGBr4M@$W>xj<x?~y_Blr6y4d6;jPqde82(1A)yu8lsXI{d;?`4p;g^Fa+8w2$UiV(3ktR@U39|T'
        'ZjV12e8d%8j8BSOIMsMU3jb}2Z?>UFbTQy9BA1!*c~-{6`KPyKHQPfG>+4+@%6Rjw2~GX5s0comhEMa3nvcJ<*$$#z7cH>!6honh'
        'AGG}5i@_d)iF!Lj3K>!oPQzEpsM4m~r?|iDtV530Pe-5O&9r$mvZdiHsfPz)j^KaEg;~=fXDNp_eCN<<Fhe{Pz}JL)tm*)jqQ>_%'
        'rWvGGb|3wt%bmsn>70mlGNyldVkoos>=baH6s0f<aA{<NnuD10*haF^(%+GCT}5VFAH2Dou*3|?7>;weJI#~BoI&vsojwXeoQYn)'
        'N&PhSHHj#nM&eA;*s8CaBSC9DT!{m%c7{Cdoy%Lh8MvSZ40bGmKEw?~4$l_uVyqzk^a#U+=wvJhxIqb_bqjwjYJSe}h0am`OG_+i'
        'pis1Szaamz1FCBC?&BE?oLQAgUhUK1gbGiJMHh-p@;Abh{BUKMv@Wgb@h5Jhob<eiaa#|2sl;ur{I&jHDpU3_4yvzmqhnX!uJ}*q'
        '<?DE0pTnPLzNzBO8jN%;u$481lx*(p!h$$j(mmFCb16EQP`_b{s!1Dg>mD7&LYYM`%v=2GgWj7@`Oh!*^^?^wD&H4C3N6T9xm?o`'
        '<k)N}Qs3!G=}&jZ=jy72(%eQU=ZJBmK|)#%rpAzWkBfb@+^#BKCmLLo`%eY9a@F(8a!a(>ea+dw=XYn5#7&A~xel-2ivFtXBrnhk'
        'XnjUKBU&SphS)IUitAQgxx2+Gy|{^VnmFm<ZTDO^nGyfS50hH$P}C4s1OPp?+*c2zMQt*Rz~(ohYa_D^CJH*2c41}?j|Nm7CY*|j'
        'TBIt9tvh~DP#h<eTDATPR62XwV#w@Eb*e&yO$j1*jU5thM}o6Svzk?1sVfR647fK`?g7ZSIsv<@xQ-)+*fVRIXF(44IqL$Tc9MFL'
        'W&LpXuy0zK)Jzvz+nvIBX3*(rY}|dAgU$ck^H~VSiq0S#QZ2!@(ra{-en0;q><)!ed=(d0|9KfQ^i40aJBzP4q%Qrb6U3dkF=T{~'
        'GM?-Jagat8xU0crN6#>Q0O~XI>?97BMl~2`ZZXfaP^v`$a2q==K6l-eDHsHEEgxDM2O8e=WHzNWcUmyA1*lx^#R*3$8B|2B0Pcu_'
        'TX<n1;xEL1U-PDC%fb~T4z_z#X?XKttI<5L0CHy~xZF|wv19|kUcTt1f%t<?U)GHOL|qdk$U}SvMj~j8Y^~Z&L?YoJAYFxM=;tcz'
        '%t!W_Se^xYlTd~ZQxqprch%PM45G&<<q4A=xS8WM%(M#-3BVX|EtL^u0Akkpt>Eiee@ID_vxF~5SlY&7BlOf|l0}l&oXFQ89SV-U'
        '0P{HkJRicGt2=ff%#gwzY7I>#%5LR2q<NQ&i$F9kiylM4ibXH<rKfT?pufH({Go$K9Hoa`{|M1<(g(0OO-EWom-tQ}Dg|s+sEdXj'
        'y&YwXC@u^n)bz(xge6;I5C92?6F6oKZ418?8t>?fH?&3#%W91%z?L*}uqpA4cM#s9h5i)m;Y*_Cf9Sl>L!hv)(BM7u(*qG>jJ%Cd'
        'Y~uj{gKKtfPy@UyzZ!Wz$z@2Zl-<n@nuBNZebGc56VzX@kJ^(s1_r@H0>|h(4)x#shmz$?b*{a5&e+Bze**1b^UoqkInXxB*c<W2'
        'gW@@}HTQ`BKuVN(h{k-7q_E6LmMgNDL`=xn)BMui6;x9eOguuXc4t0gw>_ufC~I4a9>kx<dc^A=-0W<gUR<Qfg&Iv0o}-!gB~4rs'
        'P_rEu@e7j<d{2qpS}S>wPj1p}PRYsump(2vl3>OwB(G^~r*x8bZ-QeLE0KXThw)O7c_4Y}=6f6w@(!cpispP?P18))5_{*=m|ks#'
        'vp&!G%3>Qg0`W&JDKvD77AE@myP8R~4gi0<hQlI^6?H<dI1-YXAB}Dl;6RHx%+C{5Rq4*>63X7JQ`Yt~75u9G5Y1T+F}4}CIs0Tg'
        '5tf^IIMeQAeE+!K9$}fw8Xl6-EjzY^rqlv$1Z@JKBkM<bx=dv&PU?Nx=x6{7<eQ92tM<<wZFYHd%Ztfce{}o*1Rq%cHSj&fMZhod'
        'na_JWU=ysu2L#eIkp}W#`|0<q&7tl|v*Jctyab0X+%xIFufHaA!Xd^Fe&Fae50O|9c0o%OYAD7Ig;fhUb9|mWREOCP;q1Vdv-?gF'
        '@GBI|!a9U<HgN?FFA+B43t4E@-Q|mB!oFuA_wd~7N?QBkcY_Wxt}lJGEofZ_mJ9jK=#<u?Su#t0rxjluJCN|V5W7xjkl4+D=Q(0g'
        'UR`bzm%|Nn;=fkiV8!Nb`O$n<h!7Rg^Ap%bO1MENBX1lLg3!pdqEZKT<M;e5{cOt;!NG~Rz@$%}R&El)H`LMG2#loAbtiKXmJAPd'
        '1Fbe&si%%=S;*{hDqBTggoRS=k(Y?Ow{J3&K~oxGfPO!e50$|cUrx1eXA74P^h#SmiOZ(q!mKf>uR?9aG}uoc=iT&hgp$cEmp=C`'
        '?@^w1@=>fTu+IBlhB2&vlP2^9Y{5+5BL2;8gE@6@-jce<>C4hOV}s}gA;H{;U)RfjlB|h1Iw|u+UJX%fWPAeA#MJu^f_tq!tx02B'
        'm2-TF9kysFtz%ac7IT#CK9kTdQeT0k&BC-^8kAKi0Ys<*3WzN%{*%gU`0qmqiBmvm_U7>c(TJJ0#mU@xqvRKE=kbXa&D)v4Kgfso'
        'Iw~Z6R?SQ<Wn?oQz>f-SIoCWZJRG>?X(5PTIcHRO=@Sa>v^>}8HsL-ZfD28y!7bg&w3Go7-<j6f-@`+TQwUy@z9dvi>ClgzTvd^z'
        '426p0fca*$zLe8q0>h)q!$!@~$A@`q_LM%07^Fc!a<$~e@MrE;56IIhqGPJ(@9z1PMCoRYhB$&`7OxraUCP~){w;%s?~xnA98qws'
        'fMSCCfh2LExMU&4RWL=K=%KNJj`AV04e@JasYAet%hu3goNp2TNQtgWy53aX(({m_Eu`o7DK|X?-gsn>f8WSl%Ajz#`X{F!_5CFh'
        ';d7-U7s0d9VQ3+J?xjKzeZ~90&4b05Tg-wDijP^^U_*KkpBp$z;89)fn^<)@(etr+%n)_0>K?u(P~piSF_%@E%=ZvGC{paTW?5~t'
        'tLy(6hn`YpZi-YDoCh}g{1DXHdu@@TRU=7+HUf8KJ#8#9dZj4GJi+E&k-lvm+sxWHWZX?HUx~+V*ESaN^F8v;{mUO8Y^V-q%#GIE'
        'nR+X0V_2d;dqzKv=$vafQm2kWWf~G2s1TW43aRg;+FBi5*57}<rS5>_!%DIVBGB;>b=C=iVGK6VZz1Z{>8q9QQf6PG(>`Vr&(hZe'
        'joB7xTTcD62Z*tFCe(V#wsFI4%dE9iY+Riyz>lcC(eA-FL`BR`X33E)P4-2=U)&*-n_^pgB8cE;z)`CW79y*ia|~vPd7fu9yl8Fc'
        '2klBl&Rh`|D=$V@A8;9xC*bucRDSyaP1DB!4&F-bE(SS3?F@quNzj8qXDKZ$x#Z{-E(@j0cv}$DIcrzqo~AC^v+xzDXQ0^6y;MT@'
        'h(TX3F{tw55TAV{vfNa_N&SoOVW6^E{0NBfla(JkbAmb$13_m2w0i$P+J#`jWyl&u_l6b=PyVy`Up#@*zo|O<5@(1badW%QnprXa'
        'Qq-%?7K<wHoQ*Q#$1#&3zs^+~3UeAyo4-*BvRaRM26;yptU5!k6LcrF45>QYwn<tPyZ}FPgNcSunAY_C0L~Vm*=ZbFdPKm|)$}VE'
        'Q+MKE07Mn+XMVS)V2dsoDfUlK#fwJc#85L)JmDx0Ynqf{o-^#3ur5lnPDdbk-Z2xZKN_$x;T_sHcCM0-Dc?HeVd;F+a3*B`Ewc>q'
        'nMd3-GT7`+S2GL!5YOR}+aF8&?>qJ+F9sYPStxN23DyL(zP8f{|CwZ1^Cc6L*i)k!fe>=jXEh-%ONVQyWuD@xblW$MUngwQKKnTr'
        '%+mj@r><gQt5~+P4=OKS%}Ri44KdmxDblsw{`qYn+P{aP0Euf<oB2iG8$*-?X~+b$blS+}BKSy>euq0;J^03+<tZ%#BCQ}y-fQ{r'
        'N%gk4q{h$osPb^p;!_wzk^t-4mT25?Kz((`qVWN9(E$<kk!ziWID+7`^9@pNjy}WJ<h55n$Vx@w2!DZRP&oL%(@g7+mxor}CY#v`'
        'a9eY7JEX{+I8)A`DzuT(Wx#|$?~}s#dU@g+IV``Ze7=58#yFJf*s3c8$gaK<=k1J(OWvn)M0~tDy?WTB2j+U{wsJ-_K!{5@5`lf*'
        '1e{v?VV7WZ-zG{i$?d{#LO+Vz2@d6pzmMY!AIYe}`FsYgZwq>+U~^G*fYO`iZq($sNxWgi3?JBeUVSiNjXf(n$s=49Tah5e96i!n'
        'F$`uld)bEm+;lvd$QTS|yuL7m$oBlhJ3+oMg*$Gb7FB~pG89H-HrNgo7i<yS6E3Z^E^&VlA%U7NnX8lJ7dV1u_vw|;zpgesLJwSi'
        '_#d>{r3k;MNikpGwrB(|oZjkyCYu0Om)r>~&pj6<MuvPBs#@qX@X%r}9$I|`TtABZD7w=13f-b%2Oj@6ikLKxEeX_s{?&G_@SHfd'
        'BF+R6@T*XnzrN3v{A0P$_(UY4k~dHt-rZ}v2p{+mr4M)%g#ZGnq1?WquG0Gh#yM3l(Yz{L<@r)R2oBOovaG4GOSXfrY4sftnzR$='
        '&lMBW$6|Py25sC#@_nT_n*^n8N1@6AVD<Q{Dz&N1y_D0(&$;%&d-dK}GZ}foeo(V%$BlRE>}CnPMBN;XLQ?E72DbBJ956V!6xDcX'
        'j1;UtG%15!ExUnuoWRT_c2Y(ZEfbALrjQ1{?K+jiUGb^yB`(LFyVa;O+&QEq$%-~@r(^+2M305uts=&n)IWb}wm|VQ`#YBj6eMyh'
        '`&K};u&pGRNUVRa&FS$a0+JqTMmn*~bD*y~{OwY?j_c|zI24ge)bd0ifOuT=KYN4q!)cCz0FU7Io9JnpK?3Q-3$TeSx$oFvrXCtM'
        '?<<W>yZI04ep!|Kxf%d%-IVwDk%|4ln+;E+!b06Ydw+)4&kwPskR+`e!P_O53LL^b-1Cu{=yr15>`0cV49#yk7t_ME{B?4%6B}_-'
        'tTk&=a|A=)ECRT{=DW)^OMnZgiqH4rTAC@EocK&O%mVTftqauWj=vs$u4ic#%7)6=*=#eaGba`2|C{!2O*hT#bj#~H@J7`aS}Cyt'
        'ESRY$7oi&^PuwSEWmNXtll_amTs{Jv#jw46k(a~~LH~mSV?ChzUfw9gp<@hndpoUL_#StQ66w2?+0u?*o&Z4Sy0Oj4z(Tzd1QIkW'
        'g#y=Z=mPB+^a$bWUkguv@7O@K2Bdq97C%T-mW(ly%RL1if|Lr`MQi)2*F}Q%9y$zH6c?rM9O2a1PCy3$j1`pXm?O#!-?0Q5ZKCA-'
        'ye^yDDR(J|^m&`R^?{Ce2(*!zCSU~`a6k}5;Uc@OCcNOhoj^wg81@LKA|lb)Nhrf@KeAsHW$>ZO*aNhaCh-rTSP*N*`;z;AgCx)>'
        'ac#34gt$!eH)gBrnlj&}X4NMK{Y<u%VGc(=GUi5WU>T=h=ZRRryNTFZRhx3Y>fI7-Hgd`0jsN+-lY82==A=-3OozwXkTVdsLS8z_'
        ')Om^%lK2pWodMl^twTUsipumG26wIbf%f5Jid(UA8y=}%l!0ytK}-~JGEt`J0$_;QjR~iA|5W*BubQ3Br~ip(_#Kf>dGjYtoj>ql'
        'H{@9hE7J;DiniDxduS;ftz`Lmp$^QelQE}LjU2p7)GWu_-jlhz+ey5fZGf~9#ynZOZ*e*p?FCIPpKR6~`Lyy6n_xo4fE+C7p4+^+'
        ';~>>u6XNAm1|%A9^-Wm$$Df&5#a^urA1q^GCzY#v(7pMwk3rF4R1~H}ltSx;uv}Mut~pBgOp<B#ZK@P3TH?PYxYUWp#LQlX;iRNN'
        'emw?>43$&&ud*!h929JXzoXpYTEB#mrHj~gv;};ngJ4sAd)MyoiM-zNVBM(+4+A=NP7sC{Ljcyq%dp@b4xEa1%vwWigt<+)#h(ve'
        'UU@yR-i!KfxuLn<iQD4EuR(x~mlB_JMin$7p@PM<)u{{c;e9r1|HYMnouK^q6Jy=`ueM<5DZ+V5A=ikvl;xEcD{+;4#4Nf8+K(T{'
        '9!6;0J)~i_l<Vxlrk)iaTtzXZS+k_ge#*iBN(tC@RO57#m9@Z<@L<8KO+Kd+1+<cvDVsp4uDLc{>C<phPp<(QK4F*EvmfBx8YjNf'
        'AgEqQ5F#D~i%IJ$M3y&CGWqYW5<#A~9ZR-chGe@fa=K{?XgAvDD2;AFT|Jfiix54}gZVE=)OJe{uf~X@ed*0=GOIlN&GBOXFzGt)'
        'sKB6uuoWyw$niy~mA3T0MUa;+gfb>r?32!H-*wxmO?o>Hn_?75<`Id{>Xv)BMsT_<Q+T6E`)ncz;~QlS9z|18QG@)6hjK+TX6!S*'
        'iz;epDY$4V;aR<BIU2X(?)Dn)mCzOM9If1fbq!B(y&5tX99~I`3W<D2Dysafx62Ep=A_p@v4sdES@&c8dBYjloiNHD(gyzqC3*~l'
        '>`t$9e91y&a95H>&83wrw^Yl(mZgJKy4&54ZP;GHfN?e&-hVj1gWBCUu$!~3q+NYqFlOk+)6NOsugH3Gs(TXTF5N`O{f{AQ`*{B0'
        'NsYx`EfO}>A?FPqlc_?0;I~5zu=aTUPLTLXma=+or<~OOy7}Baekl!Z4?kR4@qXrAGlbmOd<sYAHI3L~*%l#5qV9|wEOvn`$OiUs'
        'tqLa`Nu`X>&YpUwYk|+@W4|Ct%0pK?)Z~<O3E(t{J9sFZnIvI<RK{jEqTJy)aCdTuK8S))N<%qn-ZuMLhf`zL>avuBDoKH)odD}l'
        '`+^Osbdi<TP61(m055$46-ZVFh^){vc)25W{e~_~5E(@rt?Gxc0n$*cdDJ8dqNA5x7Ro-iu3L_@v2P>LdBpF~Y#jl5bPVH*m~vC7'
        '^*xgJWs9ifY6!#SvUkmPW>lXsw_Y@E-1@%Kgk|CwxgXT)*L>kNUZjbGr=lqY%BgOhFok!89u{vFq%4itpf3HIEdI|-K{u9E##8>!'
        'Bkn?N6)`G7Bmw=7lkgY(|NM*)yfVJO<?B<LM(cZFjHi{?QUrnzJI_f__*ep60mDZ+kUpVh0$qOzNn*4{!DZ>|V-x*6sDM#2qK+tf'
        'dk=X2RC-BY791l966Dsn!?2Q8Aq$!<IEfF(EgUQPt~`=Ru6~Jp&ZcVO2M|Erm7Fd|%p0Cov7=1sF!(p1wr6%-sXvW*{fuj5rR)|('
        'mC><d-NtjSmF@HCPWauq^>4I$0G8C1jt<z!kBX)##x~*U;jhDq$h#c+FTsPZSN9yFrca*%S3053e)Za*4uU|KhIjz#AS?6deF|h@'
        'U6Av>7KQmF6w=~grkYe*_(EBDDy5xC?<U=~UIYe@_mR~RwPcQT+=48XZs3eLJa?Vq8aP`0=1TVo%WJAthTpF8vc^UngXN{ZSBdAT'
        'JAkPJi0<S7Nlmqxo8K@VnO1pRhX$<$7N}wX;%FGl9uvEq*%O<Ef1^xt0`JIL1p{KQ1Y@h{77nglx)b@iS~Q(HPm#VlWB&`;JsPyH'
        'Ip=pEHxoiS!-6fI=B<Brko|p&qWU%p1Gl6pw12u=G-t1{IQ7lDWyYw(<h_QoGdtTP$DAo{r7-pkkHnl9Q$P*6%}dd=opE9!pOPsS'
        '7Wawf(YL2T(S~a>HBF?J@*`z5tP=Ecm&IVb?t;K+nJh1RCJur%PcKEw9Zr*HSg6eKFa!X0&hy7%>w!>L-L(NXBAmM<Ku5i;RVE9!'
        '`deu+u9#v=JeEh9H?%)U3ftoAm=MlS##5ejeXwdn7}^RWL<*?{^1J*TN)gM`aA_(HxI9O!W%ROs={e~@JWA*sh6%I>!&o1x+e<E$'
        'q=aTK&SMyO1&El}{av=w8X0))R;n^nW#fE2XC_Idk<7Q^3V{)ypJQaH7jHd$>>z^i-mna=Mi8y8UXdW!RmUa4Zp;Z*40J7N?Jn?7'
        'odUNd05^8#A>)kR;f76NY%9QxBoMwsL~~-_qRW^dVz4lyUbM_9@h=w&W?BSEy72ruy0pR6aA2hUPdS{11bHd?cRw6zusaa3#LlEr'
        'vs4aY8BiGsPahtb3#(1k>QvF5C?=^C8#|jH%ZC`LZ_l=NHefS~@ae7`noX;>?ai3sxfJHCH{e~rdMKinKwdbs{D#mcA(_>y^)zMj'
        'B2LW}-NIK5W|@%2#YfnQS$E3*f>lzLs?f5g2zLgt!es(I-`J5Q_$8y!2AcPLr_57(4^{J?Uc`|7o$_!2*z_4-Mynws#MWl(Z;#BR'
        '>lQP%m;Ph<$;%q0T2ckycH87uHCcLobGbpIZ1I>te>yG_Gs7PRZj+fiK*~UF4g6(iBGV*?zW8=k=|BAA0lPLmfAQD(r0F;}_0G)M'
        'e@;b@uN`=F!q24IN#bPwaI4ZM*e=4tZ=v$&sd?;@6(J~3pwmjK(6<J`Ex2<j*xIE{Fa(*SG83?V7*dl~t|V}kC&%=ZFQ%2rZgiRd'
        '6{Sxt_n$DSdnn)CI#2h&K=abh7UHNjabZZ4V1fub1qXn=_~>HKP{}_qWnLEi&KK{!e4Ff#ymh;;u(C#zMHt}<nfag^q9dQ58*|8('
        'E0L0K$yxg4<$<Ncozfg`a_|r`OHxG#E4+YKb@gwQIE2x7v{+FMX|eO7)TA4Q+dn>;q{vlM<S0@~*S>9B+qy=KTXVy~-=EnYjS;)U'
        '5K>3y!t@j@(dKs~*vTgWWj;P0!pGm_S2BbXe#_eJ?)1s)&D_gA2+!r|FUD=S2A!{k{1cd@Md>wfDMpJNA14}1U6Db<9IH9z*}rPS'
        '4hp^H?R}`G{mqUU^sKZfy6exZ<k?4rf)}wma^<_9rWL3^3!<pdWIzv$XiUJ0MIk%s?#-SOq((Et!-J{5aHgJqE^q|n4^&?gKqSwC'
        '*~jL#)yqfd*ljE{>Z@Of=`ILFW7Gs(_#^t|pD!bj9?8*>RfSf<k1^M5-rKUBv|;Qu6=rAS{qkPbfD{%kE4dN6Q%^L~ica&3UD%-@'
        'S`K<6+!hx9k8Opinq%N<1Y_;DS8#ND-QAsMd*8KvK(dekh?M48s>t<eZ*rC5!}BpXCEGQLZ7d30AvBB16&C**c5E`euigOaq-4Uj'
        '9OK#Rtx~1m3!Y3tDJg{clP~xc!K1o$h-p-+^C|L~pJA1rtjP@0bu40lf3Aw;(X-9Fp>*Dh_M8R^+wJ_AHeA26B$K;;`bf;9phdOk'
        'gyA5%jxrY}rT=bsCl+?a?-{+xwAkquUu_f@c(LiCELzn|I2$L|a8(_hM|Ep`0@teNM>D|cTt)&jF0nrQCc9*9XyS6$;;|_l(hneU'
        'l*5l~D2>pP4ap`VEwKc{8#V}B)Y?9ihAQRO;&dm~_*npVB^0f_nso=fu27acuRJsXV5DyC7W-rF`&cwIa<$Q~al}e2>)V5-Nox4l'
        '*R2~=1%=f4UK<!c>Qk(kLyaZRJhlJl&`eh{T_=Xiak}4rNZk$iB?@%BizjSo1Jd%o&zQaG5feMdAoDQij($Ff1d4_QnLNUAF-Tl;'
        'Gf}2B%)PSgMfr@7t#BzpW1{<)o79Y>2F^0A#~{ey#s*Z!ab0GAR(aXDwQ!nhz*5innr(Ld^7~8p%w<@mHrF$?<_B*eIIwzL-2Jer'
        '2rzSuS#Bjq9u#g-&S{pkTuuc^luk%&M#J^G`Hy$nomaqP86pJ(fM>{~IPbM9Gnipp6i7PHB>mhXN|d9=<8OBWO>z<$YicWSSU=hL'
        'Cav0En1VepOX^@H4o26Nu&+k!nx95Sq_DP8<)acYOPatDLjiUI=^6&WMB^FObQSi^Ucvbuk%&I+%&&VRmCAMx!+oqDzcjYEOt`Ig'
        'p1-}K#$c}7=gz2Vt5O<C8`G2s_W4JaM5!wwRVAxipa9o1x_q?B$hSD$I}JLeW{(QLhhcm;kj-M#Hv?4likPx@S{grvB+bjsrq<wU'
        '{EF`)tPsb^>goyxfTI_kpcV;sys5JoHa#%b$*v`3IaG^NM4fNJXjXbMXgTv>0Jk!XF4H>3g8Sx@OBLa(FPmGn`gh4XcyK;2Xg`$Y'
        '&Q<4msAFBlnvweEZl7(Bg-C2sReBuP77_n!DED8nEgNo7Bu72An5FYs0Vo&XbNevO%<7mq2d($1$<Xnb(;ZSma-F-v=A2K&m)87N'
        '1!HTqdNwhKKS8dwfI6;o_re0Dr;G2D6fC@9?X~r`uq-fFvzcZWj9s7rAR-XcbQr}8%}MrGg|@V6(6FkLQyw-6j5g1h(l15)z)L!*'
        '58<DWrh|w9{Q`*Eq^ONS&f_5M)}wYhI?fw!;;)5h2$rePS$FAO_uvw|Xg6MAQr?mhS!sFymOnNAAoM{%l?$5hcrV^+R6(^<cE-$u'
        'ie5ahS2tu5aFDV*mXP9|QwJm#`0<h$*w8ro)yj;@r`(g#$p9NgL5UPGwCWv!aF&!v&};J(h=+Z_U4od`Q0PwEt1$B`-pae`GDV?7'
        '7c3cU0fLoA|3&7DY%b)V>eAxLVW{4-7}IByXt=K^82lfg>EOt9qG-E6?;t=^u&Jqs_yKy%i=*tWW?^iy1AuOeWsf|GaqUwOSxu7R'
        '?QMtc0kdt6d1McG4&N==HrG=er>9=9{<S7)=MCY%`Fl<ruMXMv#L@Q*5|rnBtL69;R%!IKI~WBc7kRYBvjs4{KSkPGKyBajVuKN~'
        '4Oz4GU8r0uCp@zUVVxk{MW?U_XZw3Hc(qxwzn@ZL&~{Ebu6HnC-7z-g`-}Y5)$aJ}AP+|Ez^R5CtxqVOoun}*ZrHw|4^%=nF%3)>'
        'TMV)BQV*FZWvf0*P=Sd9eD!RnnuNC;@d41R699RIR}?`q5mjY)Fr9L><bjB6R4ZI>ZjafLmFA#EAcnXrm|{2+FQQaDdBs+EXQejg'
        '9yoNJR92f*7b}Wq+&lNbnbPqG+6GRBP#FI_0bPO56E=-v3%md*L9n*R^Ta2ZmjVWB!n?eo#6m(VD%j}jv8zpcF2C1J9J<(7&BY9K'
        '2yboDOBVD=ieM-VVR;S(A0~U;ueV=`q!YX=WNd>xiJ0nb!_go?-c*h3B9A#N$(~J}Fn&v^`BH*GLRuEHcV>xF1OwwYtb1@V>J2Wn'
        '?;uEYMHl7)QzAuqp){0v@2d>y@eiF0c1TNt(Z;io>BCKe@yoKW>zo$V|H07d8#1X%cQXsE;X@WpOVtG8Ek<*Tf7w;$l#X}1Tv)Zv'
        '%;$}hZ{*nzEN>j4b+D!@V>tu`?3hFL*S0N`m3x)sCYbJunn!ShbgR$|Qo8qCO-y-uCq7gwHw^^J{Y(!BW7guYJO_r~8KYT9Jp1QU'
        'Jx0128|L-uS3zOgMSp;_TY*C?BG<|wzRH5-l}q~rN$7E$Z=P-{qI6gSayfr_GOQRvB%F)%IdZm07YQ)g33+~w$7)H`ejU}TlRs(s'
        'HUgkqc?_UygAx*l!1RQ8YZ4x^hfa{U#+0;MhN)R0+SVCn!v2(ZT~gQEL(8R?*1Iao`NPi9P<%4xx2iT{b!dd(W<{p#n0>MQ$k_zL'
        'f%8L{po1h-;98N{say0}8>`=g(`7lwQut7e9H>%2rr$Xr&5KeyqkGP}ibM95eF*Y!({zz$uNB&rRI7RtfvhE}$)C$U^4WWo&l8&w'
        'H=<{J-n$$LYYv{9Y)v+G8i%Y^=@;R#aH2&LC+wS9w7SBrQA9v!<A*Enx6*pqHOVuAZU3Lm%0b>xZ=IJ^)9smiP)A0((rTrF0iJHq'
        '@>ylIgOUA+0}j{JPZuHM<%#9zt;P8T+tY*I00xfmK-YS)kXcz0nWjwmo>v|XuGZ?n4!ZmV&)?1%?m-JP)u;4stxzm7$As{3`dFe-'
        'a<Az;obj!D>ViiF0_?uKd^`lcjkA&#U>>JGQZgu!dKb#_#V1n?%pQf(nw=n5e1!NCvB2t_vm=%#nNU~DBA?j@YhWb6Z3yKAPSQK}'
        'bBMx1ZL5{A>D+ox-?kF&*urCwO4pN)(Kd^wZ~GEjMREYaylS6Aw?le&Sr*OOMH25#(|sk8SplAg%&pHL0x(#BH!H#)JV^K{(Y(D|'
        'P#LA5q^c%OGZl(glVom5ISC2BpAPU8@>j8SUhXiR%*X}})TQ(YXn&{oS>Vf4DOOZ7cGM&QV&l$_CMd&`EWq!iPY-{<>WdGH9z>R6'
        'uNNQ&apIXr-}_AX_N!DNK29A~{g3+v0(V9i0FTL%3zz_xe|r^r3*8`oi??64y1gR@QPZ@z$6+1PDB4Jhun<NjtRuumBv$H^tU(JN'
        'vtaIVxP^-)82~uf+pp4g7S?sCehm^q&tsWb?xPw$x1!F+4o^61R^nq#7A49paNwTwkd2Cc#(nyw7DE4sC#20hp%q!F$|U-upJ7-P'
        'e}B2-F|B|pDql5{uSkHVn7`euNF}B*GNSp+$rIuC?4W=3bZ#Vxz%*=1=HNhc_WX*Vy<iztN-&ydOSHQ=UkvHDmgb+C`IYg7;TK3<'
        '<XD+y+rP*}$3|H&8Ydm&Ky<Fr<vUisCXp83_7WAC#M0{<ai(w!-gAYC#s-6M>$iN^CnU*vq<K${TYhPJ*%hL+y<<*0DnZ-q81Et='
        'Vg*;Hu3~9z8XDkb73am{ss@jVo^^k*GjZwdPg5U|EuG5F03%%^AvN<EgCtRb*&Pd*A0fs=;4O+m9aMJ9C|^*^&6dm#1kv_;OV9!;'
        '8&2=UuH4kN9&7HPIViFVh3uL1<*oRF?*-ln&~C#-w~hubtM<kfk>@!twE|c|{p&k;E7?r7ZaM08E5Kc#v)z5$_dbNYy#;VG@(2uY'
        'Cs>~Rb*q8r2cw;Fv5KRZ*ia{G*$RJcnHA$5y@|g0vDxhK!tA&S$3OkHTj5b1O+ctTp-j{UVuEseqlm416%AkRE}NPe8V2zd<&bkk'
        'x_#lws!XO?+SJA~M!e*s=tDagq15B7Uj&7Gk-5Mb65lg3cS$WyR0*<Y3r%VH87h=4!89ll*MN1<$N{5|2RVsB#!zjGM;;lhJ$OgG'
        'Cxg|AuxMnmgTMJiyH?RAA+sG|hYnaTB*L(1-6FQUC`%}AY`}qr`%VHu=B$`47@^lqmY&a;XBqtsm`36@PZxrys!8f>L1-?)FI+&P'
        'u%R>@C{}Do9Fh*H@dlBoX0xeRf#kN#6Bu^$c@>$Vq&lj!rp?A7?mnMA!970L{&1<dyIXS7Q-#&aw$LBBZqoe=2|)%mN1{?sh%JE&'
        '!V=BeQB?dNZyQY2`OHp-msH%w6PX4Lx$^KVd=LHixS`56yi=ke(bT*ju@<ELw>fmGf;5xm(5Hl#(EkIptA{Il@`%RiY&?us6FtZJ'
        'wutQZl=28#1zo+FxNB}PbTH}=8M6c`>vU;;p|`<f#S&Aa7u4vFs<oP(#cK!C-0X^A=8tzR1BItL!bfd)>r#vwU(2wfU`)Gg`QnY-'
        'NB!{KZKl0b_PO$6^FRv|_sNgK5pxX?bG*l{xpp|p^7s6&%8cGd?7Hf?|Ev_@S3u<{o38%O62|p#R09816v6movp#@#lAI4(o5uy`'
        '!RC*gU!S_CFAxZ;TDvIPQP<K2l`(qCR;(2o(JQ7wvW?milwN<%t75lgwgZT3E0moAog+jTvU1Rv(w;@-6AgRQNQ7jsJcf~z66d>Q'
        'Jb~}OQ&XJ}iomT?#};AJy{}~>^Z(S#$q@O;!vZX!zyZFh8%|V7+B%>VRSLXG7#mh~G7u*kc!1MvH$A<6r>=|8KW4gb!1@)@d{@{x'
        'G`^LT7AFN!;9$f_yUm;d&K;662kR_!(IBZ|G>a)qj(??4N`csMV1b4Qv2eF6h`0itfdGZx-}?Xm5i#!}suf44(eT&U5zN`czwvWF'
        'o246l^oOuIQvC)NC9nxxxVkh4D9vFr1!1k*7}DqCI!tZ34;a8X&3;wx{m>5ZTQZ*9eFNBL-4<_{BYxzOifXRpMiOR7DPOB{_opq('
        '2L@*3O+EzvhtI4)7K!fz(mN?a73?c5XuS<z9hBk`uF=8sRt>AT)y>|NHpNg!XMsJ+%7<{uZFmGw$S!$X1+hlZv!bLu%L~d!uX!_5'
        'zk%psUz}m+9>@jgce1phAkCPkMitp%qXSQ%T%gYBoU-zIRom<1Sf|fMT=}JtO|Dm38D3{ME7^FprX*v(QUrz5kBQU=$>V|kxlNj5'
        'A)+*()u4-lYf-qx-yPGqh*A!}S_u@d6~@5TOo<i>7z9I1!gE5V5iDGAs9{kU%;%DNh;1jGvhuUs%xEG4>-dcAW+~L;)^j2cm?n@R'
        'k;tA_pdi;P3eDreAbU>)&!B{qcG<AhACLIvi2+#=-~5|?yD)ZE80ReTF_~7t?5df<>j7pWl2U4|6JB{Bd5Te(1`dSMiJDe?mslZY'
        'DgF4~tXfl8N>S+^2DzrQ{4^1l+yn4%Ibm@X41gJ=mDm#^qXoj5{4BfTp>?7AC%qAJ_lxa%h|Bx8kgJiBvD25=03z_;_>VqH1>?nm'
        '^<00YH_J*d+`AIuw={R*g3$v#zpnSrMPGpoZn@GSaGZx~CU@xJ4mnhGlYlQOI{(JJMnJF+nyvR9W3-rG@Pe#DM-B{#LxI0-{QXCT'
        '${6#nI^y;P*+ePONSNinq0~X!eQGtyUS{`HdAE_xr?gr%%HvtU&0`HCbMRBmG|Y48ZE1pN{-pw&s~%Y0e*qnmsk&|Z`-E+~6R2L>'
        '{0rc-r!Dh*+ft^_f)5ebcFFH1T}6%86m)Zhok|nI=<FwC5f$cT9i!tM>Lc;Xh1(OT?0Om9J`%b0eFcVBwqCwZ+o>%i_hPKN$D55h'
        ';J*R$?(UGUc$`Fc+o+Izf#Hed;}9x_GhfIdW6D_G_3>O8{Z=Nl2>7b6>CwGl^TcDlf0r@XSk<yeXgDef1j}iy%B%^W{0@p9MpsMW'
        'c_6;w2q4ww6RZa#9VSK-qD%Pi?wW?XCbtXl*I6xxKcK-I*&pqM0WM{b$vKf*b^?)l-@xuLl|RI?^_~TB{e!R)_J{<C%@ak2%vm{J'
        'tZFo5g~}~yW^~qZoaD{Tv>yj(x8z7u*GEDmJqq8Sny7W1klzk-82@oJ4(TM9r}IJkOHW|Iw099y5{qU&AaEKz9r(>9v!tfmToxj3'
        '^l@um>EbWU%PUq`B^y-YJx@nAbvr9P2m0xe&0j=72W_{iB0|TG!T`keMqxRGcadrPVCcag;G6tERTPalrmx%FKRc}i4e#rIx=A3U'
        'I|zWP@Mt_X23jzA8a+5>O}yrjHjRI8m4+0=cZ~N>MyFo~SDL4+rZ6Q?*Fxv=CDSZT5xbP1Ji*yVN*ceTKptCGq%3bkakX5{vSsB%'
        '6kJTanB#S%P6<<_uzDckNu3z9!l>a<p<*L3{1)d((CAW;0Ui*kq0Kf$vI3Tcj;8yPz?_39jZZ1l|LkzMv8<rA>WXRuw0WnXx%jg>'
        'en*VtKG4ayaSn?XZK|;MZABqY?b=9!-~H}ma&s1_gr^pyJm97B>WQ4}UAP5P8vb}_5``MHLtg%Q{mhFH)zsZR2v}9l&y*sT%Fdc#'
        'Q`r~z!uil@W&%>)Qz#t!MXn2qyC)%q1}Nx%%1WmGzPaFRX2c=}pkNhEkF+Gg7aZZj*a80ew5-qJLG{>oz97qOa<lJi=ERJM<xWt='
        'UO+$yIFAVU6p!j|J_Ht1QmdipBZri$mvHT0GDdD10>sUUhq=<@aXg!UX>&YyK|lxV<x6&~BV^SkqXHi%K{#Om3EfzT{zlinWrLSu'
        'YKH?sJefq$d2xO8rrB0kFt&uBb*UQ)Jh8RR{BF-uooJ@ZTRjmSP}h=MN^UYb(<FO(MMGA+_4f_}I!KmM9!XPNOW|^3c3pgs#OeN_'
        'RVtZ`dVw6sHI6c8s;~>UoaESCi!xv`(`@5`x1^e$FTthppZZ$L_ncksv&uE1ZKXBk*EHO>0y4v2JZ=4`69A{zc0&gE_96jMUYMMa'
        'OD-GOH06#)B_fWava7UsE~KMrE?EC<riuQN!}xZ6VrCc)=ll7_@~@HpRsJ={k7B#l-i{m$`ne`~Y$19NoHznF3$T-wR$>tYzoUy+'
        '5Eg8IMzM)y(EE7^IRcoX_BOgS4EEtH0ef6=?)9@bvbfK^d{I`7%&HJNWpb2Vxz@Rv<&v|QNY`q2p+U0d`BycH=thAd;8?J_DVEU3'
        'Hkb!w@R`j`|D=^2=SXKHRtb8-IiH@Fo6}<pp>wC|{@F!}!=af3JJCvJr9{iBvI*^8;C5*Xem_+#Y)lIuuN<tTc;<rv(*M~nfmi8}'
        'iTj=rKI{H$t=b*sz2JP|wVzXej0E`M<rGLd^E^CYjs51}mFo<Iwa6bY!Mw<;rEC;?Voy3VNKOuu>_P40^kC7zvg$W<6q)=%RdzR7'
        '!@=zp5a)MZUoC&j);K%SP|uRFc6u9SJm$PSERf1TGN?AMjSaSrK1}@HfqfG)A^Y+9ervLFF!A*$YoaU`!+OLN<*vr<1Ng<y*P_St'
        '_zHpH8w+elST}!a!I^p`^KHD`C9M78OI&hr{C1UezFmxZlCCup$|yOEGE@LHyoDxLos4`WQvSg5Z>t?iRt%LjC~6zV)Im6G?1SL-'
        'm0_)o^7}tgSjrI=MQ<qd{-}gZcotbg=TZ!!_onWwclW^DMH!jjm03*7(A;Wv;tc30JAYoUyjyr6GEwD+;6J^}(dfp|@W?6^)u9@5'
        'H%jzKX1s*H{3HG6rmyhl0QE50*9VCI94ABnaS49&K7lsee)-ehJTXTgtf8LsLu?&rBf^+;?N3#utDh$%tI!;#Iv%&oJ4m9dDlq6r'
        'y!DEi#1rAvG1R~C?}G_R3f(#0T&kDiiq990c1UQOn;Lxn3W-^=qps&T3c>skxiQ|ai($>kwgg`FAGO8st?%|}+N~F)q3EhlEnWE='
        '5B09k3iv~kI<i7qZ?8800PM{X-#hk^PLCW!{I-L+`X702icr54wDgACoK+x)Oo~BF4EX~tZAQqq(CQ$aq+TABDK^J<dz7hlXIHuN'
        '1y6i5m>PgYWVZspFDN6iV+YQqQN!PACTBKj`!2s-K=R8RjNbZW;>UnsnE(juz?DU>%}xQUBnbcwMHS{Def6{ogI79BKAHAA2c0L#'
        'FYfTgv{wNlb&ScLDO5LD1<Egldu|UjNf$0_Jm3;-8Zzg3wC{GiG=or(@f6&1rnmj9>j&40UxF(p<h;=t$ihnJL7s%x0j<7L&0FIK'
        'WB!Mp?0~qT)ZP40Gaj4Xt#{Nb>4ubrmD#vu3*!cC_7Af*!Tln+_^d3NCl`0gtfAzOVsM!*1(@R{*lH<qd;<2YGZ_nRCqMQ?>jaLM'
        '#=;jmE^w`ODAU<m<jL@C@`_De$@X~6^3hz~8CbFv{OxRruXJ3F!I}aGm0jHwQCzaPpg$hV6;nau3s+SycDb|j<&K3BvT~IIP#<cX'
        '&Sz~wKGvMee8C+?r~rI~4Lx;xkp2)v#C`%XKyU-XbDY;uM;2kf#Jf3iiS|`H8{njk$zst6i;u*V|22Fo9t1+Fyo!{Y+=*68t$MTU'
        'Sv@V4=&|WJ;zt?p2XUMaX<zika3d4mYno7e_Jq;n$kk%tI(RgK=>}dLiG|_vMH2hSwJc^#G*nrmA4Q5v8h>rrxw{Vv#bg<LJY0vq'
        'HRfCFd^y3`f@b=2mUCON7?0z7%LR$1(<@>TU62`W5m>fpF_GY5E!@7~60s0?u<ze6MYIdriymZn&#<w)oWl!GYlr>i9ZCfuRUJ|~'
        'HH8;pkQi9tU)7<4eo}o~wNgjZC#cQ_ubWz#=q01=&xc=M0EaxzTvT*d1uM$k&lD-PxM$Xqj=>ra<_f2pI8bmX=TmWmNL_bsP+LLl'
        'F4I<=zQ6i3<o|(})uvv;x=vtupLO76F_tn&7+`Urav@ht*9Di7sl>+JQmYGo-WG(+Jy<4pCeULw8uL>zdRbTx=UTg(3NB=-YqvX2'
        'WG$TUeX5Hm5EdthNt97pa13)gke>ieGJ9?FBp4KshTjrd<N7sFpqY4eRjx@!`~X*l?hE|_c&&NvNLJ{nrn=*|r{jU%FYkXan+0(!'
        '3tB~Q@`ITGSYn3KxlWVqeBhl%XSwgYMu$8Y3k)yTG60K%nE9_#Pr?1m-@G(zpU$_ni~}f{6N!gDQ9eAGARJNM?1lYeVyO!IM<q^*'
        'bG@ycBWaUNo&^Qk3$7ER_>}{Pb>UkGim=-0Y4&SNlQi!zYVHgG(DnCVc0A;;IBoSJ6C@thU3krgo&{(U62|{BqYl0e%OMAJkyGQ*'
        '9?tQ$yl%uiplN3Q-^aQcv{E-xW`T^?)Ho}vTrRsLl={Og??_{zm)S!B-mXF+*mfn4nyRugB2%vxG)&91IgvR%k1R`AIZf<!gg<#z'
        'rK57Uexd=|tRFe>*PyGt4v#9~Tn7`a0@bZn7r3n6%@J1m8y4-q@NRmpV)=rjWY^cTlj<nDZb3=15Jk+t;e4%`#7mR4Cbw{p6pu-#'
        'bLiTI>N0i@?KLG<%*LwYWd59n?B{wmEoNOiEkoChH^A5IX&imOujA~UOi;rZN7y8T9GT(?JzHK}EPev5U>YL;CAVva2c5)9bCFV5'
        '9`W#V{6Y?fTDYQ7Z^_WX?Z-?()w!AE-`_0#lX?0-)P|~UtaY)GR;v1sA--|}uw1zNk=j<3FV&GO1sCo1_SaM}l`*_3F{RJZEiDrq'
        'N}qcSe^V%($R9QvBeuRb8nX4r%Afv7u_;QvtdN>m!I*>U>_}WORJn~Pc=#xm`f959-mp)@W-*C!tfaZOjSD_)D^vqH5qPJ>i_j#D'
        'G#8{%H$gLtf{YfTFX)k>#=)6SG|-V;%2}5a1Sx%SRYU{d{zEr;O4%y6;^G#~)bdTiQ7j%fGc;6cBeLk7$HCI|qpSLb{DX^ai`^xE'
        'jK{sHco8=n!GZ5x*|pr|SaYr7fro{RSNF0MEh`Evub$d28-cHHMhxvcYyhor+H891h>sEjO7}RV5g)3PiCSozjZB6>O*zPXwj!(y'
        'z4G*^b67wo@u-K4^_F`sE|Z0Cs}kuo$XBR_p-*|{rQqARs=pJ^>tW<homTR;0v~&0dLZ2-4o7nWuYrzSMIZ<Y4{Ztf%Ggj)x-s+j'
        'h^E2d$avRz`p~=>p$0*S1mw<7U$3N1BHyuj<}=HUxw>cT*_FE)0T&fULyR0qyd)%9H90Nvo~1ur(v#Dc$#ue^c?~?sX+wf38f5cI'
        'AnKMR#o7T|by)b<ZQUW^_DPq&=9{`YcW9vw9)q2bVtwbk3vpjt-?(1j2iDqV_7H;9NOThViiu8aNlOOMg|CfjgnDY#Z$*MN&-F|Y'
        '+*-}LWT;S@o^PBO_g5#+*qnRKy&+gak@kE#TDaBukXjgl^~AH;N499Wwl}$m2BZTz_{~Q7LMra4a7cR@0hn5zUjcVDCV+H0=ez1<'
        'wa(C!ZLCrSK>l(tY;i!*yGRg*U&|Slh0(}kj?qJGo*`%Q^b3e#CfOPTBxx!79ITpL9s5uO%u-#t!{bsqHU<A|%-lUf$5e`mI%3HP'
        '9+nQ^Jt41@{bq74&zs-d0?Au>Ks*NcZ^q9hIna;%zmfbQ9uaM8`BQU4ue3anmct&m_pR{u`y53Fkc{|9gS_)|_TYIy|25L^o4{{y'
        'QgVAdxNhSfd$1GLC-xSoCBk+k?zDox-H~bcO@-HG|DWs$X6xV*E<vv6fP#T@IBZK+7Ik8ykQ<K{xi87B#mp8@14IOQyTxL}RaBH3'
        'n4D=92C7H5&Obnh$12`h;>epI%Q}zHLmbGj${t68uA7*VPy{3@k~d$OsjU8dkdvR0v%DaLSLaQ+v^u$Y9iuf+;~9YsOEAeB2bX)@'
        '4xAsx)p#A>KsdE8H1auBA!=Q+=3~;$rpAY%5M?Y)J(`+^E`8X6gh(9?9bE)$xIKk(0@n-Od3VK`*&V{iEPs4|SlVG-XPH_YOT`A|'
        'qs_QyJdC5C!RPwfvZGwLof4eeqwEN4vlmzU$FNx*SY}1JVQsN(W5&H9Ci2qERo9414xvXf`}{r6QZO8HX@60EzJgi>sU<&ClWIyB'
        '4C*3dJv|XNZ4gWT6Wg0csmd{(kU=}&aptIRf1?}3m~4*Vn#y0_jfAJ?DFBgKhnHcFVroRVf;leg0RK?v4YQ6tqk@dwUrNtMc8#Am'
        'Ce>00X~aftH#9b45E&#BH^Sz**Dp-T*y?MARDZ=b7Ezc=#LhUXuG2cKg_BdnBgL^@6!Z5VOxh2fJK54~9r;sxgQhu0Ya4x&ZHW(|'
        '-Y7=eyn0rOn=KN-0cMaQX@kSiQI6Nc-dg1a(P@+$ODeVsJVn8SlarDKXRcnJ2E<uJmBdV#07Fz&2fl8`H;|(HJmYi^(muiHXjA_t'
        'r!WL`#R)b;F|P%_#n!X9!4RA1){HEjg7~;1H8TWzQfi=-!aJkqaxnvq&WNh+#8=5Cz~BE?L`{(2Hvi}X<?XdJDjugi0s!XfjAaF8'
        '0D_y^Ab@sPdCUDBw~;@>x6LkY3<Tbj5kIY1P;-j1uLI2OC;Z8e8~@7!@1LT9jMC&!l;7{m7v@e;Q&qv$(2DXE!uM8ugYkDY!k8`I'
        'Pr&@?My(aN#dy9jIJI8r&cxQzQd@?8kwA}0U#FMj6ntnra!eh=A*+q(hP1bPDm32)5IkbwW|_s!p2W=1mhr-R!!M3G?nGjp-Vnvv'
        'Nf3U3P}q}4GsuxzfTu!WVsO_Frs|)pq1(w)6f!UL&ElB}U!3kwBT1Nq8vPf!==shwo6Q@H+#2DX<o@vJYwN+0+VQ}+oB-Ycj`4wx'
        'j#IaJjUh~SoDdZ3Qn6RG)(jvlH+cel8|MrkjD*qw?cJ*j2>5o$6rS<gEX0(ft!rSCD}n`0KHD6d5;dQAMfbuPQdaIOir=!lt^E^l'
        'o<3`DwIyb0!PRzaO7gi4tIJJv@-V92=NksN;%0GUED{uVN-9+tpStP!Iw~{G9md4rU4rRt;&#Y&3Jor=RCxufbP#>nkvdUq2&f1u'
        'M<Qn=rf7W&-|{fH0mYK?cdt4+K=K-gsNLMNwWrU&4b5V!+`&0}d><Ab)+%_Im47$qLuOwkU$yChbg@D@fRYq=3&bD?AVH)a4on1K'
        'n9Z+9+@A_`|H7t>^CQ8#5n1Cwhay42>(3M!%cpPb?SQ*>IjL{FlK>X7W^nljL;K<~fhoxyKkz~bvuW$JD;BP|oJ^~YYIh{cvM>&+'
        'H+ei7mquDUq_8nPYltCzJ4YdI1=xqkBKXM^;A0>fI!<m#zsm`oA04T1xAC&-8WcH{yEO}9+&FZ4@$NW_xFKG9ps`I$_nZIyS2*@C'
        'ko#p1(nCH;Q@N@2LE{8V43ALy{Mx?!4$mcF0<3e=gk;eK*|UX6b}#wcRE;lu_T1I`&CE%jlC;THhkT0+|KnGDxI1nVPPzFBoS|v#'
        'X>5Jh(KWKVQ$@Q^@?W&Ij9<YpPcER*jJmSz-zK@6<)O7a=z_V@0%i^w<#-$8i^D((9Z(S!{YU=9_+cT*@k3srfs8Y{_!Hfh=Ce<U'
        'K@R(m1Zw-uFjB#0sh%5Pn|`^%-=_JjR-!MPO;3i?>3et4N+>1&EH7PLT4|+te`wA;HD3-D68&3#8xq5;fdwyy;JI#~lt?_Eq2`$E'
        'i_-O-%?AM7ZY4T0h{|4cSwSHJ?#|L{;^McUa<K@i7%iS7nmDm35KLMNqw?^Qo{z4#Y2zX?A*xTCM)f33@S7mf_gh_q>i5hfKQKoo'
        '_J~S^zQqQ!%C?K${~guY3LPLAWA{_l_P|dDux#@Ebsd}!jnc#`NA5>?8NzuhK|%%<|JA%xHY<|6nA8uwNQ-ly&_6sK;{j$C#w3JB'
        '>>evYI+opSIpZOS!i$C1{oL~y=MlvmYQxA9A7*L(vU2i%IyXlt0lZRQL4SVchJEQRYca#OSsYTg_L@!V02aDTX*z0Z#Fnl2yK*c~'
        'RiI6}ZymO%V@NpDAY~7m3j;G+SE>OCLSW4@eOmDQgLg7EwBnG}GE<Q99szzMdNl%PbsFv7lgI7G#$Yq2oe{}o@Gmx#^4D!B-GQ$L'
        'K}z9oIz7GZHO#x6lfS>-GUseIC;{J8^JRaO<JQNyJj#M1$M+FvQhBGt%V|^HWo0_c?W4JOd#_rKxflNAfgrH*mt(nDVPa(Z(yr8+'
        'Q|Kn>*RSKCg^^vCB9IQ8H7Uv1=iaKyib2tFI74AU%#7vv`Kq53I^Jp8D|as8_U^W(4acP0<v4_@&xcoPrfGq{J5gk|deh&T{oi$e'
        'rn2?BGGN*7_JvEAGF7_-iTxj=47H-@ps9g!v(3-Fy`&D}jdoN}3oA9%)Rln=kyjn0YrM)Ra(CvlgnN`5EdZTY=-8R<YI(quuBK_^'
        'F_t!G7<Qq_8-5QRlwf6)6SYfOzLucy_)&r!D-?35wqj=(ua33YLi-Y8mjNb@ELsbiQ9LVB&QPy2{%=ZVThdni*q}zHY!7n#AE+vt'
        '$ilW|&csQ_nvTV-$5UM>J7WwA3<RBMh+6j9m>1dw_xpNGP7ZnYHLE!p?Zd2xU;d`Q9~w7j3cXXu+>Q*0)QVEQHg2te3#5^1!N;<2'
        'f>X^_5|Dx0j+#!_T~Uuj;m=-)4vfc{$c3%(A~R-I_IaR%%(BnNNQs1tY99JVgpNeUUV-n7ThcHcn+j}Gz0e2ug)hwU{lBap2ZLFP'
        'xxFU4bn2RSRHEMD?>0JwABkIaM$~pVQJr(Ncn2wr0{o(G(6fW6D(SoMF>oyw8e5M=1nQScEr#{gJm4Ob4puu}rs;FoGp8j5Mv=Zk'
        'J2gPZoIVHD%C<?N?mQW>z`MCQ>I4Y8oQ2_D#*q73vV-fvb8YJ&TM4K@*x91{b{O`{_DAafNhj!R$nFdtnQer;xLqu@2lMd|PYBr-'
        'k~xC!{$jfm-{KfK7kKFG=J!_X(FKuu`;7m=+ZNnQ4MVIHQFY)nA!8CSuH%G~MkcjRG?T_B>xUM;kLv)lHXM<T9|)Gs+V!v$4VR18'
        '16+j3_JDlO<ac0A_ULCoU$;zAoEiBWzFxRN+2p?|NTpsUT);%;HEAqShxB}SI!S|m2LCRw3B$KT20uk_H+X3)b0TP@xu^IHqLR37'
        ')qU-2-a^L6H%Wht*BxYG))tJWxE<!qXK8KAiheQCY?6vUw<Lip_2JiCeZ1|_D02CYIglLR__q;I48~NcvrnU>57NNsowrh2p^cl2'
        '=qOfz<Flr<LuvmzETn?(;M*aZk&vC)FZr2w7&Es$k+N;kaZk8L-y2^|=Dt;w9Xk~@^4w+u&q%yG_=LWxCS=8t)m$Ch&R>Z$C6$(H'
        '<*umPV@R_nF#KK`_P)k3#TkG$UXRe0j=YlJ4v`J4P<U7M1fZ&GsOLhnU21(&dBhtM%n63-s*g5_3CdM}OPuCO%kl%;r<)>-N7M~)'
        '9of}1TA)Vi(&eMe;Lt9kxgw{6%~T6+@CGI;K$0fx94PR92V2sZ@!r^{Vv=i#!?1NLI$eH?q;h(EIu32?c_U<^1yaDgl}p;iBdlK-'
        'g=pvk(r7s6?bGU!b&7{|m@M>KR9u6`LyTok*Ckg$byh?xR8EbJq>_&QdmW7lZB=u}ehy`Xc1~VKsHopMg!DWe=waT1qw^W-BSrCx'
        'tiOrO60+_ERdf0ZfYeYqgZm&mDQW7uhFg@M*oE%QmNL;A8rp&pH?J9SidDaIQ8=F4Updu=ZKJd!l|rWw3SV+_MHvoxBpj#|ONqR+'
        '48X)Y-#&bG-|0nwvqWruZG5eanG`6qsFL}=lkMYDMO>zwvH+p+6}8`-9=9^rFDq+@BPon-kd9`5VR~X>mxdiwNc|=6Hukq8c_NQ7'
        'U>a+}1e^`ty3z|5kaQ-OmKUIZAIDoZE}`r-mNo8i*EVJ7#Bzm)G^RhHaz{99=2vd0R;iHA23t|5Gxj_xd*OLAi6oR$A@j0RHmOEj'
        'iF}>oSR5b{?H=e7gIYY!tk&9ROB3+}Rz!r<_f1DzC>)qLyG8JINmZ)#sVExjFYc?TE5Ntu6UHQSf<Ev{<h5o>lBM~XVDh7?>RP?j'
        '0QHZWJVQFN1rU>9i{8VlKbPF6QAYJ2;Q?$u;7e2R7Lw6L*_g~S?-E8!+cJ3QK$2M=i%gklN^N{ea#mmf5@SowPz)T4jK#{HWk%4F'
        'GYYi-5gAX1|7#<&OEv|5t2aZ@;-%O8^8DCFJClXcN7q%-MyNsz0{N|oH(+K7qsPw0#eMR}L6MPclf{BjV&y(zSbvDw-rnQqppscs'
        'eb^uPWZBpp%6h))ZG|0oqY8)xklRB4j6#*#a0JZ2_OvF#dnX^!y04G~6N07GS7Z+Iyvh&PHM*Mc19sxkD$;v-wWT#<Z7gTbTR`|!'
        'x5=L0WCR{MX^Go+OkG7vgHPyq%cD=|6BL%$kmMB**D=N@IDntTH};6swNh=?6raSb9H>(Jti>iEk>D9rPydNeW5D9Fntj&J_jg)H'
        '%2%iT5R=cnvPboFJVGx2EsGlC-q8-2d_IwUiE;+UvN5N{gMP-DM1+1{Z@Fj>is3}nYK??FqP{8yVI*a2Ts((o`ZstJiywmoUjXcL'
        'Q=fHq)e`a^Eq3ToYfFw<MT9!0SA@%etpWP@3mH(82xh4y{vtT^pyBCJTsgY-`hf?t$Ta%8{S#WGGHa;LA=dq-o%WioEon;jEr8Io'
        '&b%QH;(!O)yuv3*Ess2B+TF<K!J<U3M?y<V-0|tuWX+aVe!=04k3eW^Q=udd=6(sSnomu}3!x@{MoB~1^92G_ANh7mM<xn^HmJoO'
        'J<y3jx5!~oP_msor`KoK;2_P?F<+5qPa%#7WN!&IdkuoEOg?K$7|*fzB-3|M0R#|`@#ueYrnkpBFcO#+bfL9E^`;Z4<uT~}(*}=o'
        'PL_xmmi=xETu`#4OKD~*SJons9>lhUU3k;~%v=w)42S|a5!z|3^)-uC)~T2}HX$+_MadU*<A+liTJt8kUIKNB)`!f(6@0Kcmi@7h'
        'Sp~36fz&a{a5!947pdT<A6Ew31<q}P^J0humL@RzeHeOm_bA%Q2gyQN$FN=w6@@Luj`D^-$te-*2@Y0;FiY^Y)G$^GuLG>|^(udq'
        't)*CBh5KE+<hpmztTWDxO&}g(KLz+|A#XHF>Zk;~Q<si}fo#O5zg^45>DDtNksvx+672qV*aag1&p}{f-U++jsG1UqEV?CR6Yd?l'
        '*7IS|;&m&7Y!U08Wg>#gO$&RhsHFN}`$9y+1ax<zkwS~1n<N=NhYJ!|>b!%Jk`8l#dAlyi^>vh;rmTl=@lIZl1fuwV5nh{%;tULV'
        'l?6SV!EEC%b7IZIL>sADTwbO3Su>XcMj(NMelj;q_`mxK6t+(tb~OKxG91ih?Ww(UyVZCNAY#I|v)79UIzEZuP)Gkvo8JhT4N>~E'
        'Er(@7(kIOtvhK3*j*cA~Q-84%2&Z<tyG$)&N3VeLDA>=Y-|+{Y<JKA%peWJKaQ5T>`XfGYf7GbKb`iY*dW4grHV$+e4(4o}8BQEG'
        'w7|;n6syFXAi5^4ZTGQ#5OBA*>Vn5%=HblJEQS0;2M+{*xjO#|62xRsc9#g2v|h1G*=r{o%vh6kP|xi;9^%*Aa-ua`<g;BELI;|N'
        '^L5gcK+S4t!<B(NP`VWA%Hec*Gzo7Q>OZER|F{1Fh21`Qx^v(N0Fxc5-SG+|Vdn|p=kZ{hT3EOkHK)Sqg6<;c{`8}MrnIp>F7LI2'
        'g@FKXpoo?<vpmEk7~&^t=_*dtX?YyUp%=8LSHX;B8Kqef6u?7HaMZQ^=Q+mEV+2%oM1;V~Bl3G%$SpKuww`;UD?FpTM2A)EZR3w0'
        'syZ7i-6ZYvThDNCT4$>ivMrMAMa<9H6UqVl+31m|w~Db^hLk)i4H6)y8!{hILl+TB1-b)ZCF!UKmKJpk5#}!^l<ql{Ebirg66n@@'
        'x}6ExYRo;f3PtiTpDI>#V(eDk7$h1|tqmVO;6dm&wNPpsmUnCChYcUz;Seoz6wxj+es}DqWJZXz6021jC0_1!F}nQ8SdO$s00000'
        'jaN4tPO~!%00D~R0qMT10RR91E!3Y|6c;-%0{{R300dcD'
    )},
    'budget-zero': {"sha256": '7658ba2e12248cba3bb234439f75ca2416a9a230555dfbbf47f597227575957b', "bytes": 2113, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa761SMbT8$j;0Qni<Xr$gh=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNB54@@wYZjT-L+(Hd1wR8A0;1yqK|ZsY5ElXc7m}zSDVVW<gQL#v#dTFpJzXn_X+ukH5_H5?(Nt)TB45ZpzO`*S'
        '#7)I`d)aDhF$VhYwyR9w)s|w$$VsZF#X+J=v}pQN_@OvmkU(Yyw|Ywnl~;5l&!o4T{@|;N(7Jp_EX6@#I-*VVCFNbyMhizBnu+Z)'
        'pfGXi|3>(<rLt6%PKt9{bh3K#f8IE?{5ye0NM6{<O#!hOi}<|pd=DC7=mueoSfwcW{&txj&jnSTPcW$sRZ!o+rt8LRL|EhlS^ZEy'
        'VV8tRAYlon)(yj?u$3d!HZY&kYps4N^=8KQm|b>;^Tvx}pZ{z1p9>R*PfO#-<dRJ@dB8^6O%b2oUcZKy@7JBQE#jdFAue3n13V?2'
        '#YSR!9diANw4>SjdFp?U6YeBA@#NOJols#&h=4oqo2kd^(n&L<oCmt2;Rt}Nj=c#%Vt23WkV*FsGPhC4wODWz*)4g#MY73o!RC4Y'
        '*key}9eT1Sdz^^C2p}qg;2}w$@=}k<36CnK1Okl6t;LGI>-p(fV7GZ4xF<@J=5my)V^RA!yAk0X1NZD`(ZB!z&)U-=+msuR00Dpq'
        '!4Lod*P%i`vBYQl0ssI200dcD'
    )},
    'budget-context': {"sha256": '95e908413e694b0cbf449601d0b19ba9a1f248b83638e6418787ac78b40496bc', "bytes": 140643, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa761SMbT8$j;w54aUtIt_h=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNA=jLWiZDD@N_wmF|ZpUh*xYc8Z^Ub^R-uO7AeNr>TxqJlcgHigTfm9L<v)3vGX4(!0iZ7=Eh?264z(cn+KpMLw'
        'fH$h(Y}O(b&yTxtA5&7LOOH1&eZm#0anU2W*08HXuq+L0?RK{kB?59EW>UVHUElAxaycP>zk?cixv{PX%9h>3w?-vM+oU!I?%vid'
        '=et7k=$&C@!k|h7j@@yN?eQR-X}?yZ#M|rG(c4*<iua$Zz5(j0xAPxgUOuySv?s*Fj$>|mQyfFb`7tfoAnw$}IA3hVj-VsqEj4?0'
        'Jo20~y+m_4)zD7DCzWRsa<!mDsyQarE9B>lE2YFlux~+;#^?vBbO9HGK|*T1*OF_`)eU#bqkLRz^*Fr=e^c0QlpX+(oF+h&UJ_Ze'
        '7cU9SvstNPg2>$rX1!Uk@XLZj3{|^K7h^~!WFdpLr@W}J&5-n#LsVJs?d1MR&Kz4uo0_#E`X=JZ80T>}2`Z^D?dOBtLj*#ve&1A$'
        'WV@sRtkt1bL~SlY#NY_<yrOlZ!ipQUXLoZq(UvWo-PGq59Kot>ybICH#_dpv*x=D6ECX+W4_wJ&R}LyP_#?R#Teb3gZL7-NtE@O{'
        'utCexVz}I2Unq9_^lS_kAjzei*DN7DJDC!V#nESUPfL05mV+|<e|96p>hfB2$QieSo!UD7F!)X{f0y>D*(+d0w_F2iSi8ZB?A~^p'
        '_h`#m?OGJS_wjqf#K0D17sHZxZ3Q`g^CTvN{EP_i6L!<ETmETAO<7#2RH5iyftxJh4InL1+5nuAp$42{y}pJHr5TruqWTEJ1j~{E'
        't~1<3*s=x>qjMie&5G?pe^@g<YV5o;=K?B!+TE6ASquVVAN>l+6}wa-7VyCjG|lU~@tgi7BW-+}`EH+7!-IIm^8;oE5N_hghs17$'
        'BVwg=_fgs9<XKZrNF>-F&(ID*uX?H`iv_YAJHOBdiZpKnPS$>OE&53jef9ICBDB<8{bdT~;Zl1Gbh`~@PdUjD#B$0eFDA(JAdBW6'
        'U8gdT4v6b(@d&)3*;^%X7*U-2Yy~a_ZO@q^2<J#%V7KIrX^Qt+rtOxnQ2lg&8N)T2K;gi~sUKu>5R(V=EZA~(=sB!|!slyjxz(Z$'
        '>nd$mF*3BE?eFTOFQ4Qe5kzqkVeSVyI08~b{Qhqmie<b!yl&aK-T;MN-o}iT`8-%@*mv?G+pYVK<E%IuB?h>yr-2U}CqdOa&@x^|'
        'jR1bmd;wH)N_WxwU#^keZ20%HnoqOSpvJ44CsuH57$z)p3;INs`7qQY|Jp~_M3PjduFS+?veQ+8wQT`lSb>r!(<+kQZ&4462B1k+'
        'F^J>8XXl(N%1epBA$b$TBqx#~?)3=wLs3!K0{zCAREk0UdeA}Q#KY678Lz3kaa}mRHx<zv)@@k^{Q?XmQOrz<*86PP3<SO#Sw+_a'
        'GzSqFcSy+Vff^2ws!u(ldOvqk88Q~JFWdekqXUwCVE-DWrO!hXc`Q{)I;$8=O}(f&mRfkXcx*$s0XDpF%ptvC@wkQ(GZ4yd@{0!!'
        'lwq$-bNl}5Ta>LO1Zzn&D4K%wWPh!8sIXs+uBK=+x$#lN)WN1jaB~+hBc5#2vt+Yu@-5e6%5HTVGtjnLIRIK+sYTZ>EoXvOmr3li'
        'psD}LAE?%0s|W9?_z{*fd|$Uv&h`UnKe0GfTs9#!O0ZiaqlcPyD6q(MVbC$gDILfOhb8H4xE?oKSoECZHbB=uwmE~54D)_@gH}3^'
        'g2JQnXi2UwzeGBPMgxEDBNxPFayUU~r8_aUaGU7JB$$Io{v2XdY}j(pkOog9(%92MboKs4pme&Kn>v|gYM|}@*~p@}_xAM7Qg!iI'
        '22O`-t7-l1i_ugm)<eL~(VeDU57$+0DRbxI?7#3i-l;iICTuJp>Dt2=eMS%}J`VDL*vaXeK=iiiy7|avQs^n&b^F14?w2ptmyw3c'
        '9-Z>(OPnaS4r9Uml|GIPpBjh%I(O|Xu6?_CS?%Q`wPeE{#Sqq<5DV6nrBm6vtE+CH0-K!T^tzuRykR~MpmH2|aKOQRlZ?sV-o#<U'
        ';uHPjO=Ef;*Kkq|H{#%XKr+yB0&383tno(qO!pc++6vq-YB)^f8>r^{kJ{+x-3Y=yMOT)wRW!v(?D45ToXQ2y{8Hu(WsQ~%*nFR0'
        'HMbNnW_!5lc06mV+=edxS+PfXQ+8957`g;BPH|e5NF#rn2Op4=bUN-jkB1*CqemD0;Hsa{pJl!LTv09f9Zom_iC7y?8W)OH>^0$O'
        'YfazRw!5q`DggS%u{VKo&ffx@^(~w^hK`Hqt|uiHf&h6XzxLIaDSb>PaAG`dea|`iQC~Vm5e@#gE6b(LL64w_-KM@*F*c@~9E@*#'
        '913+iQ<^zYD6fx?$vomJ`rK)IYJ;~3Wct^N`=h`!8UjgEXb%}N{nLk&;%g!Z09t(pYqUjizJa6o956F6w4PC;1y{;F-~*a%Rev+M'
        'I^4@vPOLMhha#z(x@6m!AE-a%+9)jITSMjS*);Xcm~F06fS&+q>k*WRj)5fKGORb(y1Xp1RY7{0;WYM?e8EgHSD!4*R!9URf-X$V'
        'lw)7}GD5vH@BBju!D0G05wSvn8rnl*ux(D%EXAbNvOv2b%ti`ctiAUgC~X6|We&%*GjVL!&ZzXQJFXhM%G8<@TWsqMRB)`v!vZEv'
        '1BTe=zy4UAs%A`i5a<YoDz<6g3)X|SY+u~ccxM~)YlP{-?qM8Z^)}8Rb1!_)sLDmZH9S*mD_<P6L-F3pb?E!T1_5|81-VYbfkb27'
        'J<<mC=oyh;H8AA<>H{ECgvap`Q{OB~1??k*O+0-Km9n%_Q<NoWJd`9gQmPhbrp^0H?H_CdM&<|>zxy=PmLnwqb@WWhg9FY5&k5ru'
        '9Q`}Zp;XMB>D1z@$sUD+V5*Fcl@j?R;c4EjC`!^;1wy;YBCrE$Ks;6&Ai578J}JidCF>{T-uFl_bOC2Yb<q-=EaBFr#=);-#jA$-'
        '<vJD?&S%dGp3y{|z1(nUCPm*v<O@WNH0V(`RfQY-e)%z)D;!#GfBK1gfF=b!@_9`<|Dk<3gTlz4Y7>NapyNJYpd&ESj51O1uo2<a'
        'sRme@jVvmM2J&iH205MSwexsA{2RS%|7a5b$WX~R&7hv#I$-!67(WJpCx`WKB&6mLeT!z>EkG25l^*^<pH#_U?ol<*B9}F!D>tT)'
        '_l$TN4GZ0KY!^3G7_CeX-*tHrtK^^$`d5o%ps#T*b%I`^H5@?JCeLSX`E~b4#HQ+`7tr<`ODf+V!G&eFQfZ*RC~0JHx>|hKVS>Aa'
        '`I!Z85`-}7_M}!f^#|hBnJL}F3}zq~>sD4?m+puWNiySbncdF>O#e8}SiO05^Jf3O;Wnh<jD*zhWL_U4Z(e_YD924u{O@(>l_Gj?'
        '#N4=Lx?vfKbOG%?TgdW{UIf>q5hC`u!c~3QCnlcr3=Yw}D1#_X+xjPfA^=8G2Z`DpilY$H&Gk4bFqg!?;b2{6Cl4yI8FzT#js_92'
        't11(c;Ix{?QGQ;R0jvUulpIX{ALh5AUIwEVMq#v!3_t-5VaRRPn{z)z)M^I`tVwoMv*BKStgD}`9KkFZ1X3(@?HKsj+sf6kGXLNG'
        '-~Q|}U4MG<!Cs^{P~?M|Jo?xyj_L4I72oNN<^YUF-Zo2~c-x7(<T-TZ5^;GD%10hA%jv4n_CcjP;#Bs?c(?b}SAdV3JM!9eeHD7<'
        '>U<a7VHH5!s)$iK?A{ty_Xg=f!+fVnSvOyG?a?=4aaqGdugwS>9kE?PUCC_R>yI;@VPF@Nt(NA9fxlcJt=7`H(9WjKGThYpz3tEB'
        'ePKw%=5U>MpDRX=N-b4s%VR^ML3y#$bjUh*+<`ARErD5*ITCI0C%dpvB<4l2QXTx^_yy_L^`HR?ha(+~ie*toDXPYuymuOv)kKKQ'
        'HqNp_G*IWhJGDfJXAp`>r}WB>^=9ZI@7MGYab!NDT@gOAObxKp-XCs9AcNXjRtJpYL68jXLMVVj;CUnuZK-5Y1@0TkocixFUbz9X'
        'DIwB&A<9lJZ-&O8+&fZZ+os9rFM>8S!DjQ=iQw%-F*R_TMrcMT7{E&h6yZ-r3E7*b2BYyxpTCX$AuZg2L6E~?a$YF*b{1lr3+SFL'
        'UK8os&hSZQt>aD|=MF8!czS*9G{gtC&z!SI$U!83={)ZY)(sWkp!AuhyEd~+a)+@?9H>P+M`{mjs@Kg4oeZ1SKkyR-=qIYQ_BNo%'
        'zwFI$I%DlpB=6=o;}D^aK)?o83_#1brX$%iU{N`J(0D7f6eO94>X4ZPLbp1w68DV>g(MKsNp%nd*lI{El*+8XZNtuP@dYZqE%P4m'
        '@lyEx*pji4sHjF2<Wn`ulc6!e;9=-u-Jd*>aVF;euB<xj^B!wI0V^o`GmroP7*Nd_LUB5?00H|R<H`sCtYiE0vBYQl0ssI200dcD'
    )},
}


FIXTURES["budget-mid"] = {"sha256": '7ba99e769818e63f04ecd5d607ee19c0fa831618ea7f35e868699b7f881ab334', "bytes": 864020, "lzma85": (
    '{Wp48S^xk9=GL@E0stWa761SMbT8$j?JpBe8(jcBh=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
    ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
    'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
    '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
    '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
    '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
    'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
    'ugs(C<1s12ylZNJFwDt_>Jjf`OMky(Sm@8yV2(0sy}60SkG`JG@n)(=Wj)&|#EDr|K!TGspQ+HZQG34~v@Qx;tq*tKP{@q=W#AR?'
    'EU0;`bj$U_%A{qO?9^&*gLwkwtY*q9S@nHO@b$ar3dN$LPuzLZq7V%^hS-A}2VoJS?zK*u&rk<#b%vC~`+r_r0ZO7c498SYfbNM&'
    'LS85cM2f;-+G1u@AVbSBN=_JgAn*J-%y3$FOLx*aq8CYkb{zrJVu~+kBkrJ#WsvD8DDTt7e>~7rFxjjoQ+3n1KBujZG00OAf#D5)'
    'BXKOK5qoyAqt38nIb7>lcOn&raHS4VdjUBGhAo~cphw#%*i}&wG|JreSL5=1_Z#OzV9LV47_Y$8?*v3WRS25{t2P;=2>#yyGL$@G'
    'j1WBzlQ`@oOQA|wm~Hps^A%kx@Jke~if7BzZkF|*foU#gLZ9O*y?`_O)MOnTjjp_$tyrIcwQG{Y*ht`q)Yjn@CzIiqD`o6l4aeCj'
    '@axFPd6zg#z|?j8wAsa6uQCcGvq2<kw2AC2GZslO(}Fy?{e8Z>20rHJ3qAzjF(clzR0?qjI5~VwZ;X<@zF!ThIp1|!{eq&St#2#_'
    'PEq6{A(mxeRH{UpioLVL_Bk~YD-IL@D+!QR0lAM8sTd&S!gZXvvr{<|C1#p@;Zj6SE0p%B^0Qb>$|LJ+;oJ9W;&GTZ-7?F#=FXo^'
    'ykU>B?67-^t&N^v&v`*k`JU-Wzgl+Ju|W}8T?hEGh(3MU2+jJClAns`UYH6Jn(VlaN_Kk-uQL^<9yT%hAd$P;LTE*dY&J&93>~-v'
    '>2DmPc-|~q@ra>Fmat<1vuT#7Y7p+|ilkt?AeVEhuLMk951CY&uIe%y=sHv3B|TrVfDPU-MM&+N4cgxQ?iUojkhJ?2L1>cMY^Kq}'
    'm2^{n8o#D6^Fz*W;uKb1x3WZb<AOc!?uBIlWiD7dfCk5`+r81!w;6P}hX4NhP|w5JI260`nTf1b^r%``6SinyV<M;-Rm_fDZ}+En'
    '^|n;B%2bwKst=NxZ3Yn>MQXlb)=7sYv9rL^GlNridr-U}A-t~^;6<1Z@Xg6dck)D0*QRLSWJxT|Wa?Ae<JbsSrZ1Y05a|b&n($qR'
    'mi&igU;c74{gqL0Y=OBMV=}tv#uX0j^qM?Qwi$h;d^DT?ADeT$#O6TV@yu)At=pR=Ryc+4&d{!t01z$6z@oat9p6wAE@UN#`p~7o'
    '`*Z%z*3243!)Cw;e^&CCqJ8wosH{q=4S!-_)Fn!4>mLMsE2%}84&NS-E&tfH{9&?@V1F5#$Zv$kg@<ft<iSXV26tr@37I3KhBFE|'
    'Vj6;QNk@#ru?(xH5bO5!XH=ZTkMppf!RK2U_8vS5za)PwKo_aW*b*zE$^yKOoKz<}y0dj^wXsUSlmVpGJscn@FPphbfm-SvW>=Gj'
    '9q~-s{;9p??h<};Dul2aTIVD>H}fV4rlsofL)+k^Og0EmjLQUpa|@$UUa9%l{aabOyfiTQ&){PlsJOz|xbTHmHWTB)EO$4h1AO5V'
    'D9ux{DorN7a&FJ;Qcm;a6fcpO98KJhF5T)<T|WP*mAH&tDmOiw5Dvt{N7`ic#O&C(5NRwBl_h78NLYGNZi;#me+ELstWhluffs*b'
    'A-)l?9*^j$)S?K{Fs#X(HVo*=T7~oHe@|-H6$!1!%jP}NiGDW?)vbKoWiLgz(~V<vfC$^=wx~Q3)s{Wb@s8Q5Z>0DOCP?kNP$6dd'
    'HtYkSHMTfoc^8uYB7YQRwL+bck2oh?#Kb}9z4xi2-W+(c)@vCPrC2q`#889)iDg^WKn}u8CYC$e|FLLQTnj_~vEhwXOLq-xpZa?l'
    'zDvPG8B4G9s7^=!mYei2x;k>bPP?7{rH$}K>Q7<<WpvF?2P;3*%{~p5Kj!MUf}j><8K5yfGxTEc1wi)%Ta>xT)mBRffkAL_w`-Ce'
    'h4yV8!rl)x=hPR)#)u||W6Qzbp~fd>z~F89={4~)$o3pQSiPk&mZBtXS6yDGe+p*65K*qI>_w6N8`#A~<cUj~M)-NLJB-1;Yp2JI'
    '$Y#W-pL34U>p5$Wx*b+Y;lhffv=xg`5f(-4S>A~4G9n-m13kjZ36Z504JAZ$d;*(Sfu9Su>d+AfizEw**#~_Ajh}l6F1&~V149YK'
    '@4;4x=pn(^r2wTX4Km@W4REHMCC#PgBydi32edk^lyRHu!|n@MTsdbP`a-{!R`<i)N{H76)2XUa21sP+gx<bs^z6dx&bRw&w3(v2'
    'h9;^&=6`fPlK|Z4)Qidn!Uj;Y7l)oftRYbma<+Bhw%r5vRm=lqsx^uzTo+_FSd2pnss@A<xvfQJa+gNezA$`Bv@@tp)+E1Qn92l('
    '1W=p-vF#bmK;E<uMZv!LUEW7WX2sv3{G<;xZS)#z=oga)834L?DAS?pSY=+a&U~mKhKfduSb{DVfo$|;0D!faopi_TL4sWmSspbR'
    '8quQ^#2R@@@k+#Y@d2#s0CvWev_leB*2CVB{3UhrCKoCPu_ug<@oSt40n#z4$cpmqnY4zztmq=8G%MW@$d-RnND|p?+tJjKLERds'
    'At<crRTkCmSW)Dm2Q3weAN0`2Kx-MLcs1V*kvi0>^Y>48c_;m7IL`=5&yf|`CINp}?Z{xl=a37?%|L9!mkJk-;3a<dG{$tCX+N1d'
    'PUiBwrJd{^)GraEZ8qR9&)x`Paq1M2Y@@Gjnu$xqiv=*{I~G_%;oo&aZTC#h#A+2)Ta7C_CIRsW{d&rX1ad7Sv(aHce!lr9&!B?}'
    'DLQvgB7DGmc2(Tp)9K>EaQL2s*XtL2<i1VENg(sh0a<1<7P_Mld%L8`RNTqf;_IiKBS`{`?T(<O0*RW?Lw^<mXG4ap2W4QHgY|to'
    'W-14eb~slEhW@#1^sXL5eHX-N99b|YGR%?2u`c0czNis(ORdd-;Zz$>IDI+lxVaN0u&aGY)j&>H7y`m7DW_7Pw2&EXRm-3sjyFoK'
    '2weo$Rxu&lpxKn@XEc^e6~TPwMr1}no7t_Z1fx^nQ(fQdYC_*{wFPQ#pV#tDr*k&%@JF?u#{t(SG7{fS=v#(vO4W%sgj`$NPiq~1'
    'yW;yZ0WbmG#1(M4^&(x*EVO_p3U$p2tM$vAPE)P@uh?IpDy?v^ZIa_KAlJ0E4m7($-M+ZQ$s{t2S}ABI4+Zj{DyrBW^_OMf$2U}D'
    '#<kLeM^Z#}G0Xhh?xJfzrm(*3yPN*te+6MLq%?CyY;~ncj9&B0!o>;XeX+8eP-3_f5Rm}pFK{J_Y|JfAba$SB-ck0}Oond6YGjQC'
    '&j&hd`;^csZx|yOBaBoD1Iebp8bv(rlNk%bkzrr6P#t<sl92zt50yC9^f*YQ-@QBRP70P5eBUdzYyqhs48FDqJj3d&CRuw&A_r^@'
    '>-oMB++0^2fsSPwPX1qoiU-zzw}eH5p2UuU{(?7|{Rb<I>?@B=5Yd?<+!bb1Cia;`pM@75%vt#E0=fCe;;I4RuffEh6oHNiUr<yR'
    '8{0f=iO%F(X7P~Uwx@N=WTR=!IX8TUD5kk(!eSeF*JRfU$q1yF!DrB*8W*on(B!<lt&Qf#^|_d!CvRPmDJ1qtErAK%H5Utn`$bk~'
    'wXD0lRLDaYK;T2{wu<b1XTn|u(Tg3H7a=_}`DWbT%U$bcbT>k`fvjE{r>&|mC;x|bK9ox@MoV@USN}1GHvaD+>hONMn8^x?-Gb@;'
    '_+aDu_L=2m0-Oa6P;}qAIRF^Tl9dXL{%6GgG?8vhFm>B0l*q}j+)Sy;tvau<4;gD_POa)5THOhRoBJ*U6iHv9y@(Ro46^)>!cd6A'
    'g{nE;59nxHBo|(b3$yJw7+7l)iO!yRFZvO%3<}<biu(=%lrlSGDJQyz%19qc@C;kFV??bVmE)`$%^-!pTXvM`WF%t<>h->N^h-~@'
    '&&pcLv_k5=4btJl5!i-U#@Agf#PSi1IE;AS#+2|RXwJiLa>jOR^E}ej8CK#RDQY}EZ0=0<MC30`%E$!qYYT~5Ar81~>fGbQZa->I'
    '-RQ_>DzI+*rAfuE=;wFv1t)E&TxZJ_-0xfOT!Tv3Qh0`1L%AE!&Rb-igJ+S>rY&GKB~jtycOJq$Y6y{?uEzj|elX=LIZ>`iZbl@o'
    'e|Q4FSX>pH9nk@wg5csQzU8Q#6$|>=Y@GCxx8^u^5y0U`Xn^*cT)hL9Q&1eHwlO04dIq|)YyerW^hO{pk6@lroPMyk2bTp}G|`9}'
    'C+tY}Uwz*%MiH^~`9b+Ucv~uwLmr@*{YqrT60sMKq41A^>3bJcRYlwd_+?(sEAX2vAf|<0De)joog6C9z?8w~)x@WSGmKtkr`;$?'
    'Wt4^)f!HXjTJP`?2Kd+OP3tCo#}sEh(iZ-gB$^O(L<3bHf`lN9{xN`PGTZ~uogO#d_aCRU*xhMpegJ$$*g<S5&0RUXvKpwUKEzvk'
    'Sgkfa`FC`X2rG+i9<u!ag%^T!&8~P8SA2*)Ow+fQ%J@WCw+jM12H}2O&X}P1b$YJj55)#upS(!VLXD)o7ywEIR9yK60GBbt6LY-5'
    '0Vu8toaK6KW(t{vsYC124lQQwiK$l8Gd?&Z(tDVc+%+1?E*7rHXYX&h#t4)0PlSX812=EhurmsC0p<h?vQ2r%SzUdIqd6e?NPMNC'
    ')S%XKEITz$?ct#y!<P=*LE%+F!72DT6NsM@%3tt7Z93`mG^t?wy1R-)iL94u7MrtlJT*y%=U@c7OH+Am?qG}*e?YEbJ0Q)tfMW!Q'
    '8dXd((TZ5Zvrk7#TjT$pQ+f`cMTyQg(LGS$j_4=APwUL1K}MCOKP>VL_kv8}@!;Zsd!O2o?pOGBS`bRm!aa`BdPT=L7YuNog~0(J'
    'uV;Q!IScs$X{lJqXrTH8EWn*%Ro2nV?~Qy%OA@0+lic=0A@7u=+m+&QLvHWqg<v})wfI^-D#@xye`|`HZ`<-o>C<?tGYqcXafd^}'
    'EqJlwr@<|3U55>XQ9C34efN5nC1aR=ZPui38RPNS#)teklgtf+VKcv=CibD;M84j!o`|vPjaf0~;UdOavnu!#SPr_h{vE?*U%$^d'
    '7r;2ll|FzJUbDBC6_@bg#&%Z^7fX3`hg6QQ85BIiu9M=&_UUmMi!_MDu8DM#3kb1l)~J=%3TUsUye^lg?UBi!Q|-4wQT=gm$2pDA'
    'ry#n#+saMpK~;^^dbrFFA-uw9{JIJ|gau9~;KUEi&ND?V%C5Q9VY~qLxy{4QQ_^Wu?O=xVM{BLf;;MNwu^-k@mx~T18gybw`QdJ5'
    '#335nkGzw*XU|l>#XiXY`3|B9D}LLDJk4?mUHO3?YhFs1Sjc4nqs)M5gX@`^qB1(4Z+1vq+)O%N!A{bJA}+J=MDDQs*n@Ut;^{IB'
    '(ViXxrH&(!^IYngYaPx?ZXiyA<-@i;w5t*}-3uvIg?{bW*@Zu-HQ}iX`pmF!zD%&y`?_6kd;}o5;@8-US^|EG1y%?bJ9&J7!r?MA'
    '=Z5ZpTYhmcO5XCu6oy?oBD6cOKX_D~9oQY(=J6tt;ZkzEc7N*!4mywHu&_2%8JRGI18K`G*QGf~Z}`r_`NfvHR|;)Mio7*}ePd%G'
    'Af;r~_pX{wq!B;R7$Vzuv#C)-@FVWG{sM2O=PigvxHG_Xn1VgY|G+yDm79~>1z(c7n^?HE?9l{F>1DcsfGh3yS=r62v*P;B6i9nr'
    'LudN8%|j-29?P)1EGjw4CdbXQ5tgss0nud=ebXu&F?o<((JHDQr&*}vrxFIK!U|_N$||l`vuZ1V+xY#AgEK3-RhXjSRHX*#cvS@1'
    '_0UrV>>&!01F@n$lcaZm)x5_1=4P1D>8EC&aBk_nM=o$}LcD(=3kX<5cKuaVhY64I#&`Y9&f2COsShy03gJz#z1#u=yVTm6JyV;Y'
    ';g;s;%+ApTDo(q2#I*qZa5&UkRagsYdpcqlx_p^%p=ezRC(TSo8yb3es#-^e7OvE=x%@>{p7qhSh>L23hOi&BP;IDhnW{D!K%hei'
    'm+@>jm66?KVcEJ8+1$qNp~J9xu3jPdjE|!4sNt=OZD90v<%Hs%JQeKjgFDEJ(UgF2CB#ab9ssR?+*B?t%)3#1-c_SFiRNn!nw=pk'
    'R}Qq-Pz}56sKV2H9<rSn3>z(?x@8ZHBs@;)y_Iy1eL!eV+MkUgM6~Q8hff(?f<=UhACIw>8K(Bi3c|nLEQkIOH=VA&xdbY8IhP|?'
    'jrK=~ema$Fr-oO#?fb~=TNjBG1EopDH9nY%!dvGs1s=l$IrPas6w%Se0h|gPgUN-r(Ya(fP0T9FRDLsX5v~*uf*LSTbjPcsa7w5V'
    'ZwM2=3k4}NN~Tj7&qJLT<CzNb2<g#WO}qzCwQfyiBg9D3NfP(_+@>0TRaZ{pUi0XRq#y)K9#uJXS+7NF?%`S15V6VkwE3dHnI`|D'
    'kmv|j)qBweEf_a^AO>=_2qj%~GC<zMKpYzK&cqn=F<5!R;L>BUkwDzrjs25=jDba}0CQhsMTX+kj6SoFew44u_S%!lf*aAlm)mGH'
    '9=Z0UyT>InobWF@A<ff5#mJ5eoq;St4D{ZJY@;$B|40<XM3RaL6@^W>#%?q(WE_B<r%$)Eb|A$`O%>~3<r||U`~*`(K;1}aslu-u'
    '9~qef<JW=BJ+S46zWnB|;c%Q-)bx<<$Lg)`f3MOp66P$}WXCZ^adDmOLA2bKrg$@L0A)B+Oi9ndoD{bVDRIv*F?nUDJ_$qjDJyBy'
    'Yc~1K`D*gyd#4j3+AL_{fo|Gb*sL9_Dh7>EvcqTdNwR-&T)kRH@Ra|a#zd2brF{#+$xLP>7_{mEhvOC|S{#~B$>AE7Rik&mXHJTM'
    ')_0XuVEU(O*R8;r>%Ji{C|wo*_LUYS{57Rj^7|?IiNF8o<1O}U=D*Y1J}3xstxnm|y|CheV?lW%+-P2ptCRt3d$c{uD8|FdY43)0'
    'b&FA6ZCF=WgjUUNleR$Q<A=m}7WLXNCoH!4v3=~Z?%cZ9RJbgpzU`MzzA0;V^pJ7@r@v4KUFx>r&R|1rP_z8Dar?_CQZJK3@zRnc'
    'NxyZ=@oKISNSsI>V3(8mxa<cub=&?5bbv%Pn=YhL(r<XX_N4FF)*%@JFSzet+y-N=Mi(`$)RkXOwi9~a6r7?AV<~IEq&Kr)*xa?r'
    '_q-4ZUbs@=mET+;n8rs>Rj_nDK#_UUw}=Xp^u97O>NO4fhIJAx$!H!IUS|sntG3!kLeSWq<lO)Vd<>N6#Q{^eFmPpttF#pH(LkUQ'
    'H%Wwx&V1qT{e8WZ$k?<JHc(KFQ)0SY$vcT0lgb1wkg}DULb&ls)%@rp3S<!e2f{zsuNAlWO~TL|vlltz8V3$~89koL?KJ%HvfM%M'
    'gwx(Jzc3T?4l%epk;+X{TnVk}$i&wACUK9HpCYICDhQ@_-C>>MnKTRHCGvq@*e3zu+9^%|Si4y#bTr~S`OWnp(TIa~uL24Z2rrob'
    'CLf+bFcmWeSk;|s_i1~@70YJ~o7>H<8jIvPf|(ynBm@|1uTw6QmQ-Wcp$-guK?pP;3hY+36V<*i7-oVmTg%rZzrZZL>p(USO|%26'
    '*Pe+Li?EPz71H7l?lCiTv7*4+wjeNBgD{(D#zChdiPteU^e@}m*Z6AXiqz*3`u+tM>1JD<Vv(v1*;Fod*1HpkkYr#cUrm$Myf8wy'
    ';$%pK)_~1}Clw=S4?X2V*rA53Js<5Pw_y^?lnLvYb1odCi5pA~r64rused}#!(+4<RG$Uo+SAy{r0TF5Cg%;KXhB>)2(_~2tA#;;'
    'rasA;T%t3;AS|)iwRn!eHR@=OqKli;0(?zXVV=TfYGL}Rc=tTy+f~6wTKf~y<H{;}D97liP~EeGg4jX76#|<eBZ=PVZ70G5a-`b)'
    'RAmzuKUC+Ii*%d){NMm@o~e8w8DiqG9zzMGwxTW5SnC!T1U2DxwkqFZRZE)P!Dak{_|eO7NMC&v-S3TgM$&9*Yiqo3gS-0;vatY0'
    '?oTm4hr}nwsC)j3Kcfa72B`BqT2r3J%(jLJ)c?%FPT6&9va<hmXMX$)E3rP9W7IsWywUQ;WQ}Sx3B&QmA6s16akXLwadC$}GTBJG'
    'ZYi%x+n<iLwofyIeFTEe2i82^>Rxe!Ycu|WVh^owMXkgAHdvG$e19o)>$tTzX&MY`>BDL>UQ{?>7@TyE*0R!-xvbZ}8{;H!g{4)n'
    'bFweHl?dLdLfvX`%F`_Z6$?{eQ9KVK5wN1tc^w{l)D24PX(H4JF0S+j-zi`-xj%$Z%#~aR=dq@rUXL<zx6HnchUfpE-LMMaeoy!Y'
    '?oGS|h8gopWncwO*XO%DOU1(<A&<HgNa+_ljaQ2msQg?F0on<(cNfg~I{}I3PT)KLIRr=p<v6~`l<e+>4Igl<nX|2=HX#zQRgmuR'
    'Baf~V=g~o2kpL%<@i!jn4{6&3I-ScxPJ#kpICPnwCX>0VpP&(gXJbiTsGB4-vVbVhI?bGYx$(w$RB%9ryiz<jIZ&AxqvOV}32h|U'
    '3bQcqPFr{7UiGkt7Y+I<KDP?gZ~w5RSMum%$oD$>>f)&)LwI=ZlYqh=)!&;h*)BIZ_$_(lbPWYu#iO^Z6(D1qiXGS})Uwv-N%Zb;'
    '9;r7%8^|9YiAhR;zmiwx8bWnX6G2$*3BKq>`Bd2COyam20nX{G^3CbH$$yD~VTWU7Jgq&?jsRZ-TNL7Xtm1&7d#cNH^q*+F7}zSs'
    '>d;2<P(CNx$Gzy9p%Rh+Gw*#8Yt%HSIG~57Q3D3MzCQl(-;^0ZkhK6>t?+PF=;%UV!a+7YE4#=g7d<OQGDs9%*QlM!8`;9noLFoM'
    '8?EH)(WQy7hMm{VQhuXl=~ukgv?_)wBLV7^Y88gmza;w<AFd-U-pQ_;8q>bvbWqe|=pIJE34#A(Oe>5cB*T3u|4@%P7xD0b(4+75'
    'Dv_eaTQJPBq?q2Y9W#0tm_a&;!=hW$>RCx%`Z=Oxw^ZOJ;lbR*5|ai52q-<<o_W#UTldb!QKjR8wf51CvoX|nF~Dz)TYKZi7d?^X'
    'n;)SgFDWkiwRuO8tQx{a5KXRBOt?3ZtgS;6!OgVip`N^TJ5`LsiY6~oGqDplTn9!0LF{?TV4kPUdZ7ER&$RhF^k2nq1w*qQTVK32'
    'JxOy{%hS8M<W%fmIH`qn_yQqq-1Ok;of#rnXQ6(RM}m?rY{Wy(<o*X2);ClO3w0r(nb(8K8?&T!r{im4BfUEXR)Z@~**)|{sxPq)'
    'V)}!*IK->p%r9^to@>ueBn!MsKG*0c15s4i!ws1_3<0HS4W7a`!s2O+bNy5M&K`xLI}bE1)=hNJZ0eOx<^#u@GR%X5GHm*GhdZ6l'
    '9fuFre}z@4n}}5u-r>)_R@+6p=s*ETtlK3lKHn7kOtGMrfpvHG4qegor|xIi6OuB%dtB{bzzN{fVfE}FPVoRE6{aG3=CCcb2zIr@'
    '6t{w;v}+E8Av&Y2-&A#!jH2gKKq}&cQ`YK)!v}gsW=(dkSaf8dn8)2F-x`MJEoIxihQiY}OpQLyuLIjsvL&-{VInitJEfuvH-=0}'
    'q^Fe@{*eKf$n{uOBjd_>KCWEOo<z=Z+JhY<I6Y$XTqJrqOCW$#9p{`OrVS2E5OQhgO%~k0pxJ(!A*;m_j1&WXi$qaGY3wyovL0U9'
    'Dv$l%4M9Uk?(#<ZyBYmAZcoViYo)TzQ6gK%>cni~64w9uS+#5s3#H%gI0M&QNQ+g$b@({NVF~1H@w4eA)g0Aa0vrfnRJ>rXC>!Zq'
    'V+<tc|LYH4QDvhYFe=Gf`xAI*th!ntCjB{0X<~goN^5#RB25{TnD$()-QD#QvpPl+xn=bWet?UtWQI=JwtH!ATbvtKw31jwZsi@R'
    'Zcofg{t;cZF2pVh@h{_WV*$xx)0cB@%<l(*Rseyi#iD}zR;$i^V9~p^A)9i}KKGxV+kW;_Ub1ri)Ju4s5JZXLmJpz`Ep5xpXYFG<'
    'GY#Sr<=!Ju();tI7J3~KLUm)f&(*=zbN~9~sFOe(((135RXHIa*m~&F!}BXY+I+nL@txit*y*Q8maCtYmmXioDY?q{uP$QfKL^kL'
    'iLVX%D+&rMdTi>=FB*U!%7B!rb01V@GWi%#D0@4kugKN+)2s<F;Rl<hkRvh8nCGoox&2j>2cFWH^_QO1vh0M0jkvkAsAXWjU#blk'
    '#JV^M?{KCco=j!aezF;xac7fE8e8cNd^$`c=SlIJsh`|tbbGKETnK&_$;}M8;~Oqzt{Rqsm-!=XU=(kMKZ_a8Pw2dHLqviU?f(Ql'
    'u<00_Rnf-Hr_~bMipr7C$#B;Q!GpwzSy@9mBnW@o&&FgiWE0_BY1vaW=8NWHkwT+zSMwz9)UL9Qx**%m<I3H!#!+e^T3=TFkhn8?'
    'L{wkjHksCnEz9Ngiqeut!@lvgu{7YqKh{T`#{ef*=Jb$5_M7Fjdpa8^D3_fzi-nmWzjcU9tv@>EAKx*-15iki%k*Y9VP!oYZ>IA{'
    '#%?nOgTE?#%9DJ9aboCv6uD?u?FH=jCr6)@!|~)&h$rV9-8U8Hjm_BActLmO1Bx8A^nhyQ0ANZN{&x6pvxAL<R;n3-J|0Tr^W34A'
    'f8Jq@xRcd|`t1AWAztBQBTeKpyRX@qlyM{*o}7y*fz9)?;N&L-^|k7&89Ud>*@pX{oH{w>N6cU<$ox|P5&_C+5lj<hn2OnX_acb2'
    '5;%91g~FX8(^8(=4u{Y!uNZZc+`+5DfvKoZpa+Io(nMC91POz3(X7eRqzMsQV}Eq?&To?VPXg4Bj-IWWa3O#Y%n?%4{V>=-;xT#h'
    '6Jk-euRc0XZ^`LY*+tzu1}pqs?aKIwFwIuRmb|2jh&USKYT8X_3)vzjKjCWljkYr~prmom0*Zzyq4(o|Blf=$WDtJEW)Wflmq5Kf'
    ';H}kNF&|(PSz_E(d)2&IVDYiVw}>|LLfS2T*fiUTcWM*7QG20%!NfBc>~5OD^A~ewojn9Nh+H==ZulKNBJx1}FvIt_H%9dgGzSke'
    '_tY+PG?t8EA%NnSx-2>*6I^8Q^D)XVJ!ejhn=|W@GUVG=wE(~$r8}3z2{<9B1;IzBV}fy<1_mI6A28Rt;}W+ey}WN?Yr;`AN<#>)'
    'j@6I0z?Q(5%+-|%POWQ=jl101*A|PHJ&tNt)og8Mnx(zHWk6fs6W!D?G&L$#-p$%V_8Q|Gp^yB1sCdR3dx(upsN!zN6$eC{Pemlr'
    'W&VE~{j$>2h9LKyGhP<fP=k)D(_W!^YdDDlnuMBlOL%N*+u@9n;F9zG!6+;d4aD7&EE@C?*b&4rF<^<XE}cfWh^3-)Q6tGCd9lIp'
    'xUHB$yekRgnYS;&{IYZ6=-IKQhDP{xwB4Z-M&IC8)}>v#W!r2GAkdNGeDc9QvQiRnfUNjLsYKD#$$HweP2ESL^|*e#-=j|6P}Xm0'
    '|A#d%>}O$um{ZSDp3sn0fCy9FbNXNa-+U-^K>tw6lKID*9^#w#rahrXscU4SCKS=b@~AkmHOmpGXa<G48;7T38zqtG{qqk4(F<nN'
    'B!?n@sBMSxC~3$g=j`2lC$xn|8u$${NzgP~8@Pq5pyy)b{wS{aeIk&Vfl^OSUU`A1QWdr@rmt$jj6qYlQLKlE8kS%SX}|nwiKMh@'
    'Q2w@f0uqmV22qcf47jt1d<g>u;L@^$Uqo0fXuQQSa;2QUitM3yC|vh-9tG1EJ4k0PG9DsO-{w6N`-xS5enfWgGmEPMjLjK^wvEDE'
    '6l~0NY!$Zv5J7$w*>*?Mium)t55aOr=H_4wl?=X?NB}%+kWy#F!IxkmS%gu{R(q0gzfbS)(7(zUyXG4*)U#=Gng`(&QCrcQk^9KI'
    'mboDB5~CF>jTlu%LS|!GPTf`}mMI3orw=@?k7-U%ZLu11xSKWrN+1sxQKiSwovyY|I$gBms0#iSk63WvYv;0VYuxT>J%V=3`Lf>U'
    'GiHR=>v-P>_oWa64GfJs0eJoih~b_=rY|z3%kg;to?jP^tVZoMGs3REj&i%ktL%i+-8Zin<G)Diu5h4uY6!cIl(YEzx8pWu1vtt('
    '7kNvcQz^7!!o6i7G(hL>UeeZ|mn8V2j{1}NL=p8c#%pYdiRDOsUM;sA$aQH*LM`r4*2o_QgLRpECz54XcdMa_g=5Or1vou_7$uAM'
    'V0OOwC5xZU<t)aQ774Jz$9ms7>j-cPsW+=^^sg_~sY0gvY;*r}lTfy>&6J=O9R@3Pw*;eq-P3NBKUJi1xoq@e8`!)7pzpBQw04Hq'
    'u*C+d9h#oth2YWM9$kjOPHV;%3D}}w_4xEShksCf<54ylseHn5-|Mkf|Mx8$qQ^#p|86+W!aoV3#C465wiY<VJ}n%^7kd7CM0jl>'
    ')->B$R!WGpd(N%S4}lzpCVzzWM4=oI^h1{c)3bdHrfy%Wy^PRVQ<;QD!N4qwVD^f}^+hT^)|9jKB<MGYe?Nq{vq1L9{9wFM`E2S?'
    'KL?+iWKZF|o!$5kq-G9$m0>(EATt%=8)$|dg4t`2>0Pr5d=!FLdY;3LhuZ`%KraA=4z?EFHxV7BT(RlcfJX28o#BRTk4pMV)McKc'
    '!m@c>(PB7a)qON7z`r|qzhi#bB3vQU|E674b*_4TS5g>1e)(ndOwf5WHBwZ#8h-W3mVZ)ouaI3xh9)HorM`SLm(vF4WpgAv52vM^'
    '9bOQT;4SDX4XIRf8Kp&4s2AT>9r}LogiQ3Z_kTtt1mB!l7ng7b-}7}>pPtE^;|1j2(Dk_`Kod@YTKWd%8m;6CR1@AVad4Wz(;kmo'
    '^E6i72WoT#_a+5yc9Tj4VJY`WX<HBEcM6JIjU?l-ByLsNhz^Jv>;g0LU#zDQd5mnU_^{`O{$f*^ITL=%scb8J1tRbw^w_W10;i0o'
    'B%~NnI$e0A;?~2`=bP#&#MZhNG?C>hyuu>+*3w0ywv9Hn+xuxI$5$<V&J>AI68fU@{BSvID*n|jm>jhxDRQn0K_H@_h_CD#$@=bp'
    'R*PKuMObt$xN=aXj^Si*FIxJQ`_fj`M$|W`(taR-B_=whMtDy!^)i1szsj_0@{w6u?;o4T)CpcurabbkC)=>$sc~Uhm4SCQ6jw?i'
    'yPE$#ckYTAnlq5(;T9*A3&(zqK7{h>l<+acF@XZV4XrX^K9Nq}_bhL02j{q=+a<|MzVBxr6?eL*unhOxxE7j-FI3J^Ro(`s9Tflg'
    'a??Sf<&LX&?Nm=tx6&;kpVp$q`lL}1`)^NXt30$+PYqC5gpUcX4lH!*W!7Sksg2c|mm$B+$sFy#39(^}X?`Ml{dfgc@6N$f&YY@&'
    '%bXSwaG(FjV+6UE+;OAk=%qUoS7GFJ^Zktgf$JK<A<nSny7rwQl*4RZ40_<oVEcQ*T_@;wVC$r#<=kSFFDK02q5uy5S`Ggi7*7xg'
    '$VoX8|7Xp4-N#6k3cT!plNWS8m?Q8h2>yV7G_ZtQDfu;S5KMwW3;VL2Z7c15H(`0=wONuGQ@=X%r>kTd9WnLGNkFH`qFf`x{y=Qn'
    '4u7V;3OPysw>9=0v4F(Ng$#?M?QV%xpt^N5w5n~vZWI$KO5{87L!ex;Dk$QIc|AoS0(t0Q;=d%LjE#+-@%!*+t%E6MB}TqXW;j|B'
    'm&maP9=e9g?F*keSM_W3%ztY08_|hA<$dBgpw5W4_(`3bSvxGWksL%T0;Uq)gD{S=#3gSzbp-r`hVT+H49tbO$SxJgdUBBXWKKdl'
    '2|#*1d)mb3!iX1e*zZ&6Y2>C1e~nvxIL@po%iV}EpcwhlN<XAvqBETq*@kUrjOUmhDrs@3yC-z~AX|h3kF_8UK_d`@WmSw&ekD!T'
    '^((<A5XGJnMM!dhzo1DZL}w5_v#IS9I+zE68U%O|L-}u^;qw&dgC-0PPFi(^hSATa6+pLTy)+@c;1&A9>9tL>>eWNJ=BmE--dBUM'
    '*5Bo&OFd?RP`feYKIU00K057nyxik*(e6>1#}^v+3U~vExG@rZyQw)~m8`4z1{1MYWOct%Er4lO_I8RpGX-#^Wv99fmXoR<!&l0T'
    's!hGtiIa6Qch>bJxtBG~qqq@`r^FS)r1t!GO~2kOX3cWkZFm7)L2(lmc=Jx0Q~s1?cS(epyud1oslF#u!&lHt_zh49kh3-|;=9*@'
    '#{d&p?5<yalR@$ooD47lUdN!wq%%b9w!hhM;!w~b*sMyX3PE*&kvvN0)3jL+*fb0M`dkERVrH95|8I*J7d$F`cX!|emjO+lQ>a!R'
    'nxdYqz~<TDt&k343?v+R)JYS$UmU?cH0k@Zf89J>>-VH$2pc2InVs!0JSN-h{>b-eW4+NN?^O6YRYShMb|7GuH*z#uUN#L&m3L!r'
    'A!%#HK7b*clxw}{+yC)%x36ge5aHa0EC>4!A7v6dXp#yGu7@Wb5v4{e@M>v_M0t1`a=~{X2auy}Z)&^w!6H8jp<fsy79_#iFJu~N'
    'eB+<1OH`;wAxPdF1>mojBfD|I4+Y}f4_5&4cUeC#Utk|Up_F_Xll7B-%A6mB@=RpI`-T-wE3)%*2Dx`3<~&O)2X|KWTuH^9q#(Jh'
    'J$|ai$;3e8L}@wU>mg(!zh)+iQ)NVqOhSOSt$>zc3*##Z8o>i$kw#tAVW&h832-{oU^tYSnd<2)OB--eD#MWW5CI!<tbGkA+g%~K'
    'WcH)6uwQ@E5@J^PDi3>+!|kZ{#CO&Tma?_!k)Hs&c^?avJX26tI=M2$i>8VI&T|2-)oIo8J)8p8%tCw49wf=Q<|PUYbJ_R=y~}bA'
    '_m?t6qSCd;>LYN6$;28RsG(@qrArkhke!^_duyNaO=H(@v=yNLJY&r?V!ZHX>#xPt&xlgTeB>y;@2?mca~*|nrnMR9XM1;o`t_}X'
    'Wub;E!?)juv>ump6x18*6hIRWiUy?}zi8f4nV%i2786|!W@%c;?xnCjE9@hU8^=Ph)G*fggvS$I*9clM!97PlBOQ&mPJJSyow~~Q'
    '7N*O@H%vs)1K4PQW=_9QdsSUbZKu!XOI5;^`DMFO5Y~i<&(k;oB*rZ<X4q_|kbn7fOgHv$-Wh0wLSGEPegxE9qRfvH^blueJ=~^$'
    '0N-No*?54iCFKwXTl1dY<L|+DBz%h4aS0bK7WYvZtu5)exWHh1M<w&LzL%e!U-r~Jd8eEs^P<B}Tk_c4x0^Vi_yF^QIL~hb|LKLm'
    '%P)jF>bs#$R54!0ZSF{NqKL<a=XR*n#EA7LR2+ph09EUi<LRsr#yTD8Z_d;kjX+jK9hnx*OsQ5iH|1Ubxr4MJneNoqED{n1k0Tap'
    ')v#%v?Wo)?`GvbvbKd-8wKsA*eqk(C-Em|&C=(MvZ?h(>88rs$`S~Q4?`MzAKyDm)&Y@*I-~mZ+f#H7gR42l@b0KfZ@+tk@$UxX8'
    '(L{U5IoXN%xP_T61G+2XVV?P+7CX6>rA~l~D07KMT4(nH>dn}t5#lWMNDv#Shw)9UR0m##sZsM?zR@b+^?`oP#iveI{o&GDdj6F`'
    'yjZ5pNIwe6SS4{Zy}W+ufekjTj(MRCx)BM7oYHm#KB4J*EBcf;Go8|~M6Cgqb6VF&vO=)ENJWtM3c`eK-x>w#<#0CK$82eLQd>2D'
    'D*xe0%V(?@ZkuY>*^NpI{gZmtIMT1^e_&7K$sxR28L4<P@Nl35t1(K@N&{#MP2efesOigA27s^@D)cqk)%}4{(S#!WOxLu8^{X-a'
    '*w}K?#k7h5=NKDHAsR_7UBO(UH8IgvS6>a8pS_O(!p0LR;ILD(#$8|ElVc7Pw{>3tsT9UAVVU~nE4cZTaMLph2KaXq$1Kvd(6rD+'
    'Xoc)(vItULi~1YE*<R7eTt(YY3gL6bc_HJ_$#ywr6k7B`A;rDe^s1^FKH=Q9kPk=#Y%aH=qAF`g)EE#nuQ|0>c`&FGE>LM2JS0O('
    'x73~GZbz>*LcHPUrL!ZQzQ^>By7}@98Kl98jiPDxMg?j}WfXn7KfwN8mcE`WcPs2vek?v8V>V4dj=3fBXXyGCbMi=)v|M{!C{+DA'
    'tC|M~r9hO}ytT)X`P6ADNI`NFR#K4BKYOEn{CDR_lQ>aM6|IwCz+z5P?#RP6iYl_N^Ee{~U-32Tv{0j_Y&hNyOED;D2gB9hq&Q4L'
    '=mgUM)Ld<@z-c60?y*>lRMF;#MJ<vMoBw&w1V@^)ZKyG-`q1S%*ijVzg3F47!P;*_U^Huv+PgdpgB!j_(%Y;r9_DlDF55t1<?tJ^'
    '+aY=?E$MM;O<QqNBg|~>gTRT6iz*+CFwM7LIHnwOZB>dzJA!u#8F&;W&9#^6DjoWjGErdVa>l?&(jKGZ24VI5)T@Ej8QwfmozDVc'
    'mqFkC>yTyD3mu@Px8?U*CCaq|M!A`4<vXZA@I9rwZ)t?2J&q^yl6W!6<c9QefNp~F3_XC7x=xR&cV9pctjDh|r3k<-jpg}ik4dlF'
    'jv)o{S<tlh!9<z*_)|1^#6w}Y5tMi8oAMBRz7}HaEDP!rhyuMN>wZo2DsjiUxBhchoEZwL18FZc_zSQ;QA)YN9_bVJ9|$AeH_BB_'
    '9zW{|ir{@P{%KGHq$+Dc^}#5BWwWCy#TF(%+=}p`{WD+Tc`0b&G0}&?psmBq%p<Iy+3Eh2vJ={_EQI$ZwF(C+H@PnN%B!$x+o9$L'
    'pWVcHC@#|-zO)qzA330d?aE!uR<ij~t5YWawTHA8=OUhJ7(JZH$2w$)+d$!>*aMaaZ`EC>gFQ2@sOh#J8VRGGO|7pCp<D`hEO!8?'
    'YY?(EpUO|w-59S$x;WIS$I0m%$)Kk##_29@lGXT9m`#^_*#A~6uYZX{+JMVaO>=yiECO=5-in4)VHCk0N{FULMp&y+VK|0vKX+i~'
    '^)??X5753tYeT<8)a4*LTau@#jqc#{icAKY0Z0%FggcAN+1btD=ZTDq+Yv^cLOV5FFX(SOxUE4KJ93`p#^+FH7FGnswdL;of-qbX'
    'J2ltzQqfSr{eK0TXes4}9+#}{ceP}`1p7k)kie9aD-E`YkEINbTVFPHQZPK@sBihdgSG&AF4JRM_wlb+lpfgU=Li+F2Qv`gB97+W'
    'gGDYy04^=h=RSz8r66yrfCHU4N`6@O`p<CP=3aV*d1ejPMUa^dBh*Rs3e;D=4NOewZrU<>XvtJZO(M1R^k(`I+E}W#v~P!-?vxa;'
    ')i6|3(I5k)MPjSM`R^4cCvlO~BWz9vTS@#ao-}o^{s`f`Ag^%B+w*QmWbw1}K<RW*eNGw#PXEd#2{XP+|6!mFcks`*Fu)%-<Tm4;'
    '7%Bva<GEjJ9YKK6fT_(9)R*NhJum9S<GGCD0T@|A`SPO3@wnGbA##dBlObO}_b9t^CPZf~{H>LHuOb4d5)+qktdQy@`8fo)UL;^0'
    'uei|@$yYCH`Gm7R=kRL@{>3bsS=3ePYUA7d-uJxx0uM`Aa5kv8fx=I$sx9{s^#0m!Y~vg<&5Z<A)iIeGI~|ew63OYKp;lXQ^E^aQ'
    '%glPlriq>%ZsVu61x}VcRXZ3^G+gx(yLrQ!hYDM|HtSL)sg7@c8WIoqzlA)&F-Ldo3f4M3$IM~0i}JRU{y`HM2olXsDj~D_I5UV5'
    'S+P;~gm%nrZgk%{W;JE;hi+EivFI}E5G2jz<|UZT3U<ZriK@cs_%DY6)pLo79H?`wwbZLbOYISWv|lw$(+{ISXUk?7Ske+m3uZzl'
    'TPP`%hOyr*A9EzscUPK%y_IA%QmhiF)x^BEzzYOARe5{O4Dip9sur2ELQm`cx%##c_&1~KIR|2rt5j7pq7SMs14=Zhe|l{B6}v&('
    'AVOhcuRWyuD#t)hV($^)Q?!C5@cgA~BU<(=i>D9698WOH8n`}@ppN}fGV9taMQ><V+d$BJG_A*9O5vU!F<~3fpm_EaBAT_QX~Mu^'
    'X|(p^<dMPDY-1<=BwK(pc&R{@o?G<@r@uCW*KtT@hVvbD>N_c+GG_9++bE+<4;1pkUkl#~@Mfgc#-)tCXneE{?Y{6~jl1JAJAmld'
    'y9)w4dwXHqCg(HHlTLPog|zMR?Iars8=6!_g@a;^%1MwjK~?PYlaw|vsu;KassH1qH$h|#Vr~c59ph(M>Nd~Js@M+*TONr3CPTt='
    'T4_MN6ZSHehq)D#@}i0YxyH7cAZDL1atqVM;3s*XNg<(bcd^c&N~LgCQd>e-M^5>heSKJ=$1kAT{hPM#K|v`{|JK*4y;d$fOhI(q'
    '19cG&kEbnT7fWMd(}zlXtVoQt$#f6^%5Jl=1J(%f_Nzs%%1HIU`m}K#4NtZzCf{~UF%RNEhU9gJBDvR;(4+8V<MQIsf;?q|nn`@;'
    'hn7Vb_z06qY7=*z609g9d^7eFzqwV3^9`PwtJ$m<(&cKMurjQ=u0|-plaP`Ce5~&Tj)g3+0WGR15@=3_G%5fZ9{Uatir|xT{++*?'
    'e=7~}KFR(9+nbWwl^M{PIb26LXpkl~Y?W%pk>F`-#U7^&6xOrIA-%_^wWIIg1Yc&TuhdT(v@<;nJ~*@C<KT&~fteqNmpW&LJoQv0'
    'F%t))xl>FcD7wUnY5@v{2lk3S8eY{>hUi&k+&*Q$f8+EwzNqFC2Z<qrgD8e;(<9{avt4Q;2*{Mz+8nr?z2&+Dh)cZ&a=eNxz$p^a'
    'PX?I<YQ?|>M29o<eu$klec1g$v`{^9znP1HhsM~v0FaUQQ)I!OUVKs{nct-1Hsks4_^WZ(3e^)}=mr%{C8br&UXKOSUN{`iacyrT'
    '__10pWP>Y;b~WDDs2WEaJU4KCB<*#<B9d&s;Y7>rv&&mC{(@_?UcF}=dfGA!zp6x4RKX3>D}u7OWNuDchRuYPb#A~Y(7U0}&im>>'
    '^hn*ix*_T%6y;ye4eVa?p2YL6BLX5RmB$>&RnH!A%4KtKhAi9NpOGVPlj{#&t^R&)6zy2a>7S^y8v_ZcI&5#6&5qbVbB4?kOhK!h'
    '&W`r2y=L6(+KDGkXplA5V;0{r5py*p>kdd~Q2u=qhQ1#QC)7VJFaFxBVUYFSh-)Nb)S2ahn}jqNg29?YxQfdhTlN_hwjV(qU`)q*'
    'czVp&WlcPon+&@7y~|NefAwX_1d7OL)GuTQxeNF<3k~1UnW5YY4f0<yGP}hkdZV~de$anE*;&}zKt)i5mC$Z8WAl91Vx&7`SLhvP'
    'SR_p|^>;om{(Lf5v1^{nEM_aZauerwJ4L+*$oGz|8cpFK?8&n~Lhj9$c8z~&N#n*$IsZmiNF4u9k41FB8e5u`c;xfAJB&tzMk?S@'
    '?&$GwL!Cs|f{xboxputmN%<KKc(5o7*x*n`J&cw|-Aynxdf~3N;3B&;DEFK-@9;NtOFOG<ZlMAZ-{+6N)pO{wxH2L`sMT^{zf4$o'
    'vq4q^zqhZD?$S7ov%AuWz)5}1H5Vos-O6MpUSp(zQrr~d0pK}%Jzp4=OaBN<FVUG&?&w{~`$q1FZcrx(%f8qYex#CbTVl5xQ72Bl'
    '6^Drxg~mHtckvIwLKN)gq!pfom;2J``K?hPB%|zeomT)@dtyBlBGuxk3r2rO^j|JSt_ZWMfq>b|?DUGU{}X~MT1c!VA9B(_uFHUZ'
    'cyDTh+DI}I+>6ne_ZE0CcXbu^T_Y5U`bsm;)sfC*RhSyy>l$g&CPbCmj$i4t2D3zWW&3*>O4QEt8hWY}&xzzCjZ?vGh&lR2bsziU'
    '(;uh$>}qqUd9sIS&F%|o;|>KF)^DVK;VnvvHfTKm{@hhc4gEC6z8B;?2G0>wr|Y?PPmWScZ=FaWB&Ko=_=sP2i>6bCf2246aG%H&'
    'fJD1}W7Bb|`ud`NoIR7}BN^v9OAh1#9f7=b_z2yoZSMlh4p#9$Um3(;*gs1Dlz2IBjl4!m8oQC*?Un%g1-8)6R~RK`T=~z=llVsD'
    'ZGnc>_!Q#joJc6PP0z{&RzcywPg?x^FVZ!FG*r4RDY1zt4h&U|>-*eJK2Bk78y7uzpkG+`uph2vC54NeWuhT?W4U^2-itGR9#@!<'
    '!rtG8PZCy-`PXXR^-z4D>xr2Q4SbawDgU*_Ys4PRX|QXxQv;b^yox}#1_-psCau)2f-py9`*FYL*7~M&U*{UHb^^{dG$;OV8i9g('
    'FCrPgw~`;=6nCKl2n7J8`wNjSsR(S7Ojoj9=kxn9R?xz3g5z&Zm;`rRY5P9HZPQ0Kq1c<Lv^P)_)`i*mgEYnljVS9NGKtMIqt%eP'
    '3OP8{@K5hUn$2V7h0=%~L%u^Pq_|@fVXO!=>|5$cOt*A1)l<Hdl=|K}t5+%+!@M-mWGs-(!m4S94_!{l4Lu?k#W`ws+E8zE>yGy?'
    'xwO0oc>ePOv#ZK(t?^9e-#sTi3}Yh?q|P^b)IA3NemN_@_mbXybMM3DDlUi32INM1EM1_BGJZGMm<@Hejg<%t^!cx4U*CbD<Z}1c'
    'bbZXA5Q;>8KXgmviX-u^WN`y4qjIWPrcix`99*TG_PQfkW0;dSh2_qUQ*l*WO?jGkms54G6Ba<M>>6Ny#Y?=u&0Au49|+XPtR=*6'
    '-ECcRO{}9noZjG@Y6dW)VQQ;23%aOJgR~EdMJ=AOkDXnJ+ADGDtkOz0lIyOt<CMAB0(cHMfmW+pW$=dB!xOiJ=!h|E>fO^fDa0!x'
    '?<LVybtqIZFmbs#=o6X6y?+C|IaAnfY3HgM+kqhfnH_%BInie1t(M^l*fB=eEmwVF?wQp?|H`ifr9>@L`h#HxcCX3?FWQ;$d^d3E'
    'gd*yvGW~cUhX6S3s%G+;_7E9S$J>wUx3>1v(<TAK#6Tn-aX|pJabADu5Y_ju%)~%#20o6Z4?f&DsJ(|^YU3<52aH4Zx`_;I2*mk$'
    'MV4_+%6=Fj4nK0Aj+snks*r!ZN9Et<(+<fztiCn2G5M8mClANRnGKF~<spWf*S^|1f5oL1Z>va{kpO%gy@C9P{Twlyrfrx{#zmL<'
    'zBBI`a)Ocj66@L4#;@-qsf_iA3g|<hK0HPEiaR@mA+OpDKFkZzkQCq7gJTY;O(+WD1TEU125%kCPqT1%Lkj1+ykrpudM`Nr(~67J'
    'L1QFyLLc<8l(KH@_qe)k$_B~)O=#eLS`31_ktP|sZYgQ3aEy2!wd5Ql3W;7J>bN>hlILw@s*0}@l18r8${!`!*vmKifk=x})FD}$'
    'vS~(M*w`@-9FIY)I2No?tns6_1J*`-y<>dIhNX$|-%M$a=g%vkYB%PA4XXHCTofhW=vs9F9-z8-Q9q2coLMFwp_L#hq9Q*oR}1Yy'
    '<0JVIkJSv%w@a9c^mW`|DACQ#xK&Jk{HmW4kJqU<H0F1Dl+OFvY8}N$_Kuc~X+`6QOi|7rfb1y)V3wlem)0p8HuUDKp!G1<BpbOa'
    'peA^tjiPM9s<D>Ja_g*hp6vFc5Y^OD#~NdAEUwvUpOl-7lBEKQR_s7Px4T1y%GiaG<mTGxK_jPECr^==na<TR05U*Vt6aO=2=_y`'
    'W~uGrb6!DdPR%S{C#CN0%3E|8&vouKzLSp%M4hsK(l2P3lmQ00akmjPtp1NaxW=T-T9AjY2^|CoT5=4gq#o{3?^zbczVD=Vdeo5>'
    '8-)I&Cx+`Gjc@UYb>Gc(KLOfbGYeQO#82GOFxT^A3?oS-6iLc0exya%M=J}pDg(L7<Iaf{Wds>`6wf@Tg}0PAvfh@;#+=A2T$jgw'
    't8snrGPM&&h^o6_>3KhA(smucM6ZYh-S8l+^7^BMM?r_^Q00;Yv0ZDRIbdVDS%3?>%GK0KoJ8Jh2cNCX{PCkJ(*??zyAC$o7(&q>'
    '{J!^P3ZCi@%?Nr#t;!`t^ZxA-^BTvp3XLagL#G%4j>O&e)g_=*CJR|7eiN()c9uQ~O()PvvcOSty^FSTbH_xIj~?=44B;VzH1jUW'
    '74-{As37eE`<Bq1d5MQfnO)mK<M*lNkC@%-5M$qae1wKLV(bk2Rt<4EekJt7mFV#vmZ;JJ&>6DPoiBf(Ra{M<6{?lxsH&+UWwra%'
    'rvAqjz+Cx2Os`D!T&*6@OLbVPm&?fXDr%gXp(0S2*SQNRseLZ1?N}5AChGG@ODgGxtkJQ6-}vn}xYW&cAN%jjK8hYwE5`j4tEY*Y'
    '=~c^!-Vix~PTnN+<Cx4+GVYgth1%|;k+)_Y3m`MM&P~k)&VAyaLC5g1fRey1YOt>UjUIScp+=c65>e%caTyuLvxY)F1q4JYv?!;E'
    '3VDVwl~G{ytET0JCP1!QcC-tsV*LF_f`t$JI4D!8P~qAOzyqbeeLNh?R^k@)+guiP)2RwB%p<Q|Mq|Qkaz4-*UFoFqh>vH0_7$~j'
    'KtOSh6L7WDb}`CZ%Xlwckv;T=!#+j?+WlMX8hhR-rV|S;`nSfRP9<)#Z^u8B13QLzia))cnFEPD?{!TDt0xTJxJR#I%*?YHJI=Ct'
    'og$KfBVx;&l|%e@72H`1-~1=AX!>7<>&~8{Ckh@jfjn4CTe)4emx%Mv#VJi)%q3D&SFLI#yHNZ6t1=^WXvG1kdz1D!ZL0?)^mSEa'
    't<)9oTtHZ7ei{MwlY8OqhNQDvJw;pHYQu9y4^<kB@(xG8Ov5Pls|>7F;L2;(lw7P%QK37chfa+0?JH9+mQlI&!^~Qu?4QgdMSG=i'
    '^f<0urB3ThEbXR&QK>n`DjmiHVhudJWyFk=wc99tjb>Pw73!&DZq~QV*Gd|iW5|oo(SAh|>z<kRZqV|kyCA=pNU(iAn#u8~obgrh'
    'VWiJje#JxSMGS44UY-56{JHJhHb$Eb^!hy<Z+6w|M#-t1MdaYfQO&^5uX-O8ilhGPQ&{CkFY9|Izx%zE>|E1qf2x*9#R$HhEPnH~'
    'tv?53<K9!C+p^;}&dfYR3UOXdx_~+@d-s|WY+*u-h_9I}(}#WaTh?dMa`i}0T7P+STCad|IF~uuik|eCXl9F)dYs-T?9F=}dKv|m'
    '!9Fe*hh0ODnf6M1o*Y77g#Dq?mK4DOae~by?Elq2Z?->}_*C|yZtUfcBq$R}<9=-1e4G!6JB+KwN6m&-8VU8+Lq||i?zn1u0=?z0'
    'iRand1t`5rG5^qj7iBgG!xjZ}^tHAG&hd2xN6Xk~(<q}L2`hJ$gSQG3lOd|PUDN@~t8FW<t%VvkdRXa!WLvufspMKyDKBWZLKuFK'
    '3bz>Q;4g)@?Zc0HLs)D5&j`Z;!7HXep7f)5ufx5>`9fTb>{qtgHOM76D~d9!HgmbxclSq2l-^uowEeH(UOps7XG2E3{tcHTeD>nG'
    'U00VCr$wEMIf?1&*p68E7*@DyQK<j`1tD!SGNv}w;Vo&ZYNrlfY*G4pigF!t?!SS+cM#?2cK?oZ#YBj7K@1n^UCtUN-Vhj&rGAPp'
    '9)hJfVm2THpP4+zyeuOxK<SGaq<Lj1w8cL5>C<RyjIm%P296-ZR*1npHqtgt{rpP*k^UK{`cCg;U(M7btzY`kd_J68CN(Y<cK@N@'
    'FyjJIwVI*10YaaMS^7?;2V1kNqy#2JPcjhSAWPhX9IwsX-(VTDic#y$Qh=xiH9k&eKu`TT;mVPOOnlJd<jzMu3CM$>W*I4W4py~g'
    '@01?n5kQH1nLOFo8pcUl4Svk~KK6>8s@5OWx;9Tge{Vxf=1y(2ttbKo(yh$Q<fS(c9a4+1?gR9sacZ8w;|2XhRg&V!vvz+l>9gFC'
    'A0FW@ahK_)Rl*M=9_e#dkmuhzLqc&aPyu|5+Dus^zn1w0;X>7oLNMFjdBH1vG^MM3xf#>-1Sum)aQ_itX}NykzJm5cDc8nyOWiSV'
    ')_e%$9?Hn~p-B2vW1*85wADw*OxByCQWD-|(|y{ZfJmb%#(~hN`tI~LryttFimoRY@+|2`U_#cOXSL~e9ZaUB`Dsy<7JUgKN<Q6N'
    '_7}Bc{m()h-2TkVO6*_}mYM{O;0_k_F2po4wTavZP364`6kxpK$D^A_>0%U3B4w5ptY+T*ZsyRvsaDgT8&7PpbO%laB4YAwa=cE9'
    ')f!>$SiO3+Gva=x`b*+xcD<XG<O8K0?4RUMF&j1yo6I)|;JY3f8Kj3CHVNyej2h?3*~wD5L=1KQW!;B|FVysGFg`?d|LK6S-pp0q'
    '@#bZX-b=H^b}}b@P(5^F<XhNG!|8_g&Fu`Y>?>n$yMM^j>DlxR1b;Si0Y7{b7bKfSeW2^HbO2-}4$IYYkqa@6+qhky7R(lNCg%p@'
    'm@v~#+>q9kdMs|eh92h{U3ktT+Th0>Keo*^4o_g?@ReIk0y>@Q9is`xD2ijy<|eRc-;02Y`@{=d?{QBAAZuVL^VH=^EuL8-D|S>n'
    'Snw1lE7s32Sa=<(3&D}{Zi0l)b+O<0HKt0%e~Limq9i9Hm^wGH?iaDP;MI!{2TbGDc#)9SPw)1<e_7r}RVOPk1ezxG357+ct$My9'
    'cTR86?dRDinWK+%Q-JRU-hibVGtW7h{&O$gt9Sq&H0>G2OshpuAP--SlHH5^b)<9Z@EO62Eg2zaR3imQ&M#o|s2>YQ3;-iCbLx-&'
    'sa4PYjD$6=J`ZP{(4PdjN(6~Sq<||TK|OS>IiJQMh12Rw&-_%`8yzoyGxW}*r{FQ@kB5`M<Ql?7x>Hu3Mq9s_1m{@lvHX9VIoIPL'
    'ONIQL*Bl53tDnK-;A9IBmJBiF4kD;`p?$+rxD6OQF@MP=f@h{dBS`SlBLP{`>qxSW1CybYrsyZzCE*s%!wmi(v;(R7Cbc|i8Gw_a'
    'wqbl%?Jw4A9X}&oj8H*kyYAA^xV@@9uS!~{(#0S1bVMM96fQ~2o-y8ziV6tgPkc~6cUy8Nqfmx~EF@WRtD#58kwUP7onnN0(Y#d>'
    'Q+JD*5luHHRhB0qqEz093YQ)yf%wi-2X!9q49=q{VPPMab#xPiMpJMghk}HAc-%n@NAnnX{BDbo{841tmkrTfBplG#TMr6!xzcln'
    'lXN`~S0DE5zd7|yW;m@fieOWb_&VF@3yE^lY+(@aK7sENPc8~5uJ$+*L)wviH1gPv<)BHFrMOw!&|(Z4Kj^6EhXq&DruCP3Ys$qq'
    'ICD|-E?hlM%@qIu1BCCpVv&Zg00Fm}0hHb}%%g=PvBYQl0ssI200dcD'
)}

def decoded(name="tiny"):
    item = FIXTURES[name]
    raw = lzma.decompress(base64.b85decode(item["lzma85"]), memlimit=64 * 1024 * 1024)
    assert len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
    return raw


def rows():
    return [json.loads(line) for line in decoded().splitlines()]


def find(values, kind, predicate=lambda row: True):
    return next(row for row in values if row["kind"] == kind and predicate(row))


class ParentReaderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "evidence.jsonl"

    def write(self, values):
        for index, row in enumerate(values):
            row["sequence"] = index
        raw = b"".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in values)
        self.path.write_bytes(raw)
        return self.path

    def reject(self, mutation, label):
        values = rows()
        mutation(values)
        self.write(values)
        with self.assertRaisesRegex(ValueError, label):
            reader.read_parent(self.path)

    def test_all_26_real_records_replayed_including_duplicates_and_misses(self):
        self.path.write_bytes(decoded())
        actual = reader.work_oracle.verify
        with mock.patch.object(reader.work_oracle, "verify", wraps=actual) as calls:
            result = reader.read_parent(self.path, reader.options_from_args([
                "--rounds", "2", "--attempts-per-parent", "2", "--screen-width", "2"]))
        self.assertEqual(calls.call_count, 26)
        self.assertEqual(result["retained_proof_records_replayed"], 26)
        self.assertEqual(result["raw_sha256"], FIXTURES["tiny"]["sha256"])
        self.assertEqual(result["counts"]["original_make_completed_proofs"], 14)
        self.assertEqual(result["counts"]["research_completed_proofs"], 4)
        self.assertEqual(result["counts"]["all_work_unique_winners"], 9)
        self.assertEqual(result["counts"]["transaction_fee_total"], 3336)
        self.assertEqual(int(result["final_stats"]["chainwork_hex"], 16), 12)
        self.assertFalse(result["native_reported"]["state_execution_replayed_by_python"])
        self.assertFalse(result["native_reported"]["clock_attested"])

    def test_zero_budget_native_fixture(self):
        self.path.write_bytes(decoded("budget-zero"))
        result = reader.read_parent(self.path)
        self.assertEqual(result["status"], "process-cpu-budget-stopped-before-context")
        self.assertEqual(result["retained_proof_records_replayed"], 0)
        self.assertEqual(result["counts"]["acquisitions"], 0)

    def test_context_overshoot_stops_before_new_acquisition(self):
        self.path.write_bytes(decoded("budget-context"))
        result = reader.read_parent(self.path)
        self.assertEqual(result["status"], "process-cpu-budget-stopped")
        self.assertEqual(result["counts"]["acquisitions"], 0)
        self.assertGreater(result["strategy_cpu_ns"], 1_000_000)
        self.assertFalse(result["controls_completed"])

    def test_complete_before_budget_but_admitted_after_budget_is_not_credited(self):
        self.path.write_bytes(decoded("budget-mid"))
        result = reader.read_parent(self.path)
        self.assertEqual(result["counts"]["research_unique_winners"], 1)
        self.assertEqual(result["counts"]["research_unique_admitted_within_budget"], 0)
        self.assertEqual(result["counts"]["all_work_unique_admitted_within_budget"], 3)
        attempt = result["attempts"][0]
        self.assertLessEqual(attempt["completed"]["process_cpu_ns"], 50_000_000)
        self.assertGreater(attempt["admission_completed"]["process_cpu_ns"], 50_000_000)
        values = [json.loads(line) for line in decoded("budget-mid").splitlines()]
        find(values, "strategy-end")["research_unique_admitted_within_budget"] = 1
        self.write(values)
        with self.assertRaisesRegex(ValueError, "SUMMARY_COUNT:research_unique_admitted_within_budget"):
            reader.read_parent(self.path)

    def test_options_exact_and_expected_external_pin(self):
        self.assertEqual(reader.options_from_args([])["arm"], "integer-paired-general")
        for argv in (["--rounds"], ["--rounds", "9"], ["--rounds", "1", "--rounds", "2"],
                     ["--target", "00"], ["--cpu-budget-ns", "-1"],
                     ["--attempts_per_parent", "1"], ["--cpu_budget_ns", "0"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                reader.options_from_args(argv)
        self.path.write_bytes(decoded())
        with self.assertRaisesRegex(ValueError, "EXPECTED_OPTIONS"):
            reader.read_parent(self.path, reader.options_from_args([]))

    def test_missing_end(self):
        self.reject(lambda r:r.pop(), "RAW_COMPLETENESS")

    def test_missing_discarded_screen_candidate(self):
        def mutate(values):
            values.remove(find(values,"screen",lambda row:not row["selected"]))
        self.reject(mutate,"SCREEN_GRID_ORDER|SCREEN_DENOMINATOR")

    def test_false_noise_score(self):
        self.reject(lambda r:find(r,"screen").__setitem__("score",0),"SCREEN_NOISE_REPLAY")

    def test_wrong_selected_candidate(self):
        self.reject(lambda r:find(r,"selection").__setitem__("candidate",1),"SELECTION_HEADER_BINDING|SCREEN_MINIMUM")

    def test_missing_complete_research_miss(self):
        def mutate(values):
            values.remove(find(values,"attempt",lambda row:not row["proof"]["target_hit"]))
        self.reject(mutate,"SELECTION_ORDER|ADMISSION_SOURCE|ACTIVATION_MISSING_ATTEMPTS")

    def test_truncated_proof(self):
        def mutate(values):
            proof=find(values,"attempt")["proof"]
            proof["proof_hex"]=proof["proof_hex"][:-2]
        self.reject(mutate,"PROOF_HEX")

    def test_forged_trace_passes_cheap_target_but_fails_full_replay(self):
        def mutate(values):
            row=find(values,"attempt"); proof=row["proof"]
            challenge=bytes.fromhex(proof["challenge"]); task=bytes.fromhex(proof["task"])
            header=bytes.fromhex(proof["header_hex"]); target=bytes.fromhex(proof["target"])
            # Public deterministic forged digest search, never a valid proof producer.
            for counter in range(1024):
                trace=hashlib.sha256(b"invalid-fixture-trace"+counter.to_bytes(8,"little")).digest()
                ticket=reader.H("ticket",challenge,trace)
                if ticket<=target: break
            else: self.fail("bounded invalid-trace fixture did not hit")
            wire=bytes.fromhex(proof["proof_hex"])[:-32]+trace
            reader.work_oracle.precheck(challenge,task,target,wire)
            proof.update(trace=trace.hex(),ticket=ticket.hex(),semantic_id=reader.H("w1-cost-game-semantic-ticket-v1",task,challenge,ticket).hex(),
                         block_id=reader.H("block",header,trace).hex(),target_hit=True,proof_hex=wire.hex(),proof_sha256=hashlib.sha256(wire).hexdigest())
        self.reject(mutate,"TRANSCRIPT")

    def test_duplicate_native_admission_cannot_add_credit(self):
        def mutate(values):
            row=find(values,"admission")
            values.insert(values.index(row)+1,copy.deepcopy(row))
        self.reject(mutate,"ADMISSION_DUPLICATE")

    def test_all_work_denominator_cannot_drop_auxiliary(self):
        def mutate(values):
            row=find(values,"strategy-end")
            row["all_work_unique_winners"]=row["research_unique_winners"]
        self.reject(mutate,"SUMMARY_COUNT:all_work_unique_winners")

    def test_chainwork_cannot_sum_sibling_winners(self):
        def mutate(values):
            row=find(values,"parent",lambda row:row["round"]==0)
            row["stats"]["chainwork_hex"]=(2*(row["stats"]["stored_blocks"]-1)).to_bytes(64,"big").hex()
        self.reject(mutate,"NATIVE_CHAIN_STATS")

    def test_phase_cost_cannot_change_without_timestamps(self):
        self.reject(lambda r:find(r,"charge").__setitem__("process_cpu_ns",1),"CHARGE_DELTA")

    def test_budget_poll_cannot_reuse_old_permission(self):
        def mutate(values):
            first=find(values,"charge")["budget_poll"]
            find(values,"charge",lambda row:row["stage"]=="research-complete-proof")["budget_poll"]=copy.deepcopy(first)
        self.reject(mutate,"STALE_BUDGET_POLL")

    def test_false_within_budget_label(self):
        self.reject(lambda r:find(r,"admission").__setitem__("admission_completed_within_budget",False),"ADMISSION_BUDGET")

    def test_fee_receipt_must_match_actual_header_commitment(self):
        def mutate(values):
            receipt=find(values,"economics")["receipt"]
            tx=receipt["transactions"][0]; tx["fee"]+=1;tx["after_balance"]-=1
            receipt["fee_total"]+=1
            receipt["after"]["accounts"]["account:"+tx["sender"]]["balance"]-=1
        self.reject(mutate,"FEE_RECEIPT_ROOT")

    def test_source_signature_corruption(self):
        def mutate(values):
            row=find(values,"task-statement")
            raw=bytearray.fromhex(row["statement_hex"]);raw[-1]^=1
            row["statement_hex"]=raw.hex()
        self.reject(mutate,"SIGNATURE")

    def test_missing_original_miss_reconstruction(self):
        def mutate(values):
            values.remove(find(values,"reconstruction",lambda row:not row["original_winner"]))
        self.reject(mutate,"RECONSTRUCTION_GRID|END_DENOMINATOR")

    def test_reconstructed_proof_never_earns_new_ticket_credit(self):
        self.reject(lambda r:find(r,"reconstruction").__setitem__("new_work_credit",True),"FLAG_FALSE:new_work_credit")

    def test_reconstruction_cannot_be_moved_into_selection(self):
        def mutate(values):
            row=find(values,"reconstruction");values.remove(row)
            values.insert(values.index(find(values,"strategy-end")),row)
            # Preserve monotone observations so the semantic phase gate is reached.
            row["observed"]=copy.deepcopy(values[values.index(row)-1]["observed"])
        self.reject(mutate,"RECONSTRUCTION_BEFORE_STRATEGY_END")

    def test_no_model_utility_promotion(self):
        self.reject(lambda r:find(r,"end").__setitem__("useful_learning",True),"FLAG_FALSE:useful_learning")

    def test_previous_native_schema_missing_initial_stats_rejected(self):
        def mutate(values):
            find(values,"charge")["detail"].pop("initial_native_stats")
        self.reject(mutate,"CHARGE_DETAIL_FIELDS")

    def test_duplicate_json_keys_and_sequence_gap(self):
        raw=decoded("budget-zero")
        self.path.write_bytes(raw.replace(b'"kind":"start"',b'"kind":"start","kind":"start"',1))
        with self.assertRaisesRegex(ValueError,"duplicate JSON key"):
            reader.read_parent(self.path)
        data=[json.loads(line) for line in raw.splitlines()]
        data[1]["sequence"]=7
        self.path.write_bytes(b"".join(json.dumps(row).encode()+b"\n" for row in data))
        with self.assertRaisesRegex(ValueError,"RAW_RECORD"):
            reader.read_parent(self.path)

    def test_raw_symlink_rejected(self):
        source=Path(self.directory.name)/"source.jsonl";source.write_bytes(decoded("budget-zero"))
        self.path.symlink_to(source)
        with self.assertRaisesRegex(ValueError,"RAW_SIZE_OR_SYMLINK"):
            reader.read_parent(self.path)

    def test_raw_replacement_between_stat_and_open_rejected(self):
        self.path.write_bytes(decoded("budget-zero"))
        actual=Path.open
        replaced=False
        def replace_then_open(path,*args,**kwargs):
            nonlocal replaced
            if path==self.path and not replaced:
                replaced=True
                other=path.with_suffix(".replacement")
                other.write_bytes(decoded("budget-zero"))
                other.replace(path)
            return actual(path,*args,**kwargs)
        with mock.patch.object(Path,"open",replace_then_open),self.assertRaisesRegex(ValueError,"RAW_REPLACED_ON_OPEN"):
            reader.read_parent(self.path)


# Exact small native v2 records, collected before source freeze. These are
# correctness/censoring controls; their timings are not formal performance data.
BUDGET_NATIVE_FUNCTIONAL_ORIGIN = {'source_status': 'pre-freeze functional only; no performance inference', 'baseline_head': 'b33a30fae35daf79db6d03895c33311dd36820ea', 'binary_sha256': '785850834e4b4c1363a3bc83e87e4aea00dcce82e7a69771fbf1868421a91991', 'source_sha256': {'trillionnium/crates/trnm-pon-node/examples/pon_w1_parent_reuse_research.rs': 'aabe7fc6950bb8e5550e6ad4151ddade1e643d8e914cc15d65011434a4f6d830', 'trillionnium/crates/trnm-pon-node/examples/support/w1_parent_reuse.rs': '2ebcf7142c99263047833d41bcc1343e6c89fa56655bef1c049964358c0b8e90', 'scripts/w1_parent_reuse_reader.py': '091f29a1327421d3700ab64a572ea3f7950a936b1032cb818a312b3dc74124aa'}}
BUDGET_FIXTURES = {
    'v2-cap-hot-zero': {"sha256": 'c38765ef5052c17ca527e2cddfb8c6e47790d2aaa1a3da8a1c19d10776fedd75', "bytes": 2187054, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5|NjPFV_g6}h=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNRM?}(e>7C;%9bL+Q>C+Swl@wP(Og3^j;&6Z2EjgBhP^?;-%cQZ&*@hk5gYBgllId$_yMi)v8<m}pLI-+uX;TkU'
        'o$G%(W<mIC7SLp3hY}@RbTDV&=wucJaLX-T$yc)^xH&F{Qto{ppCxmA&BY2A%@DPNj4(?|;#dj6YK$!Q75;LMF&U4!N3RYdvBhS;'
        '=d~8jq0ZnTZPo~@D6{YkTEL=|)!;q;!GGdPL5`OhRdqW;8JVzY&3kb|gtSx6Wri>SV6!}rGg;jDh~-_Q7Co>nu0zA!7H@Wl?k+Hk'
        '@iu%k0B2PE|8f}K@Zx<m`VaMN$~GHyVx~BPzozOvO>u#^il&dJ8@urusT@1|@IZHe+*(l|Mv0<_1_}TqiX&=KT~>$gwSDlfhHZa;'
        'FyKYCO%&*lqfZF<<w~)y5oL<pg0T^9C);~nm1iC$+;Vv0H+n~;<9lQxR7wryqKAsMNM;y7-##~lJz(8!5q3}_Qod5w&-2&DucJ1G'
        'b(@LAqUez<K-ITx>MFpY<RuDNxUUpR#&2K(RfG53+-@^Il<_qu0F}-s#*y3OpnJP%N!^fy)wNaa8}t3)jT*?2cpfH0`ZHhh$)Ox7'
        '!B7NeOnN06!cR#w#V2Pgf^Ij)8(ev!+Z$)hXl)<d*sO{9pbvJ3%eFbdNlas(0Yaa-g)ymC+poV%?J(<7)jf`OJW*-WRu)4sBdIuP'
        'g4N~?kZ)J49u+HfQ8|up9ijNq&N(^?#vp0CRyM*G<CaFWSs|TofIQL#$)iz!%p5C37P52k3F9jOUZ0oUCM7Q~I4OQ--8&Cf|K@Gn'
        'rF^C?vGwec&<-pr+ipMX7Y8B3<8J2Zsi}Ltr+Z$BJI*Y`=R!yKhBY=Sa&vf?tKMu3Atv4FgB^tIEbHhZ;4gYvjvKi|z9LVH(D-?u'
        'FrRoG+EIQxesaWng`V(MXJ_Ua32X**A;z^w1Fwb4i1pi_{-Gw^J50z>|EXf+>y=|#Mj!-7#P2*@M3zU{8`pACwMn>Q-Ugv0q1G`m'
        'H`cr-;H139RePmn9(Z=B)VY><!X0~ZV`x|4ALL~K7nT2L3%Hm3geJ^4XKS(@iYD7BBLJ+FD<6mLC?aui+v*@L2ufX3VB39X6<%Sx'
        'U!;*KazFIbY{Kdj`ZkP1w%2mzey&m7*{CIMDQ4#3tSlc$wWXGAz2F^()t0YaysASQqZ&7s@i=2x0Lp@~ESGH`W`~{|BjbSC+GtLr'
        '+=Ow#DiZ=(*%I|7L#zB1>e1D(4m#B`ouc-Gd%Di$0ewlvc`*F;UtOkLf#pAFw!Wwj6Ma%9)mXf<w-!oYHF$bC$qt%#A~k?HHU)Ob'
        'L@3fH&^ln6kyqG%?l;7;yLqhIP#a?rJN;7Ov$CWM?O%I1CWGQ49*kIwqoxZFVOHrT{04+_Zz$xL;KVbJi$4HTev1&yvp~XVWXrH*'
        'bAt*k-ebb|O^TNr*#4A9$M<x7oSEiP^UuHzQ<(cn2bdPi+A-;Pl0(iCSVv^LJtA728tw^4i-^|=I^|A9l#b#dwJJTSMq~RDx?qxj'
        '#sxa(<m!uKyvqVPVF@$R8tU;o73?TZ?`ussY|db&LzPSZYLHf^=42wBrBU!=@Revd2*a<ckj}yl>m{$J(#HdIe_ukyBzcZ6yN{li'
        '*_@0_QCVO=k~Ta3P7)DFbrqGjUWMk>T>KV)I=&bu?$<Rc>Qf$Cgq}q*oFDm_ySW@9=t|vMOwexV_H(Gb00wRsn<z~L7#p!QD51jC'
        'etQ(Ws{lwF4c{d!gs#xfITOR;N-h}>6YhIw`e&H^pMQM=WM!Wd8ZMhpAz~|4xtUJH`#>4WNaY~l4jm`c_ciOgDn7xL<y&a-CEZpT'
        'Q}(xYU9wC-oCFLCtcVYe11Qy(Qs4#_75WBkXcs*kCH-t?j@|JL!n&H76b(u45l1N9M2O3#>Xsq<F8#fNJ{N!>oRfW-#7j9qN<2-R'
        'wI=hvDZp%5{&m2*Rb{lM23pj)Cv@Jg(bh^#t!w??K+pVeU3&TrJqK$*H@p%1X~<?y92gN~o%kKF0s~cr${rDyayM-ozZ?vSV#mik'
        '{MxWIZGPAbj(`XFOXEXlI<8UprM(ho6D4PK$i;bW(T!$_?8zWTP8&JNM-wvWrSg$u`pTL?`eWi_V~CxluI8l9@u&{B4=Hg+G-KGH'
        'OGGL%#yFPISk8=!-^*GkAw|ofM$KO)EE_DvX-GCP<023E)Py>S+y>0Uk*O3>P(H>j@$x+D1Vuw9C9pq2kO`D}N#`S7$$+z-@`tq5'
        'g&Ud!U;NP^q$MR`5~=O4HgP!ds3jc_DwsW}3l}D`#Hjv?RnhrC=sJpc!f3H?mUa5>pHW2;f#4HUgyYYv@eQpo2s7Wv_-)nGM#Ygm'
        '1dqw!Ac!vAI2^typ}j|(mroHRKcVZ0t{p&{cU;V|r^hiIqrmn#o^&zB4?}SOUoVYEK<g}oYBma7C_^|={@vmCtXc;)3a+I!Xza>A'
        '7ZS=Y>j6}<EndYr4n&NG7u79BcF?%gJ}8^j`OfEBnLGt8sqz$3Xt$mqm0*d(t&s2xiF2=On!U3vGR!5jGV<#uNpD@&1X&C~T&k<*'
        'DIB`-7+#elh4P=kYOP08U+b0qF?JONUBx|kKlT8UlR0t#p=AJ%tMyg>yQ!LbT`o6aDpD7v=+8)!{Ub?fMYKxq<Gq&xnhS#LLX}}F'
        'o^l)OMit13HjgtDc@9ToBZT6Q-E+>HWmvRO7>r!uwZMBnlHGisBd&%r?DN!%vLWFuiW)A_V<K^vW^Waqc@7v$g~gHy|BlV){KQF*'
        'K;}1=Z*z7o%8}I#tbJbgV|S=Yo0LS14yFZvK?|E&V1r9$%DTfpKsu}5&kxC~rKc8~xol-MG%!-nN8@S0rE3)b4*BekaD?WRFk+p>'
        'XRNM_mk3i0HN90!mC1oya?~N`ug_~I9$ie%dXgCe^cV&<x^8~=2%DI<_OJsca2hZ95#nn0%lDNt5uqCr*XOk@t5|B={cveqkqJ^2'
        'Uq0~H8^W=u*cLSD`R#$)eF5rRBVx%w&LTKi;$)&Z*uErGxPt&3mm?7hPZ_k@jmz?~#cxj?+QpFf5)qRXE5PP*x$p<EH`=OK=-D$%'
        'EWhitdEEm;d8N!VR&s|(bl7Y5W8J}L48`S!Uaj7o!F`x)Cd7yY|Et;grZv`CI>1XDXPJsV-}Mj-Nm9u-dxl%e%+|5!c+n0ul02!Q'
        '$AF_C@F4ydgaj){0%P+;Bw7*RYg9?eGprc+l9d9^k0t3qF&}LE6Q#UaBT=9!^hT15#c6mGJ0j1KqzSmV<^V|^L5wDut2o#~W~GN)'
        'Yo>L8l-<fon@J`~Ar5-U=TUrxIB{5EZiO7kz!~^)l&#CNAI{=YdN;K*NDhTZ3RkO#F(Ma~N8twAzBB)s5TS5T{2*gQwuNYzC6&J4'
        'cKYvD&rC{{Pi%qqmkCh(fgBBd_6KuPVckU||4IhfJ@mL7+iUeD&A5;j(K{%oyjlEr%3gziU#`B2+4VhRZHBdEE2O@*=%TPj{pk^n'
        '&hG&&j!OGo?VD9@YVx>N>A+1;6Hh9Ih~*4s3sjRSRRy=?`NjK--{9Pn@wZ6R^Q7()9M36dW;sg3;DYFWr!vieVZ%YLtX}Ql6(-)`'
        'LDt~bfZ+>4N&U9#>n=SOPzAN7t}*T9q~Oxkf>L8;nSo5-riE=<Fx(nwlvE3M{*MAlm)AJ1V(_XP>eoB!T;U&W#fkQE{ZKWyC4eT3'
        'LyNiM1P*okD(=O$R}@{`;}~o2#rha1s9L~zd&c7uPH$S^mkeB(A}=nvD<(pY)BvO`h-yrxcx)X7t<E=2h%UzH8(?t%<=IIthHdPL'
        'j-)V7_`Gd}`S1ZJ38^gJHNql+fVi1;R~rl{l$jdv?s7CK#9v%Gdnao&x5B6`sL)Vlmm(jHNTh|sV?0ov9BUXDRLws;gH4vwj~*d?'
        'Ws>?o>+TIES}fX}<Lmt$;4=;g>BF`&;Hu~iONVrvNodNX=(O#_m4-oB;xM_qppy6`JJ}XK(QSARp}6YiQH5E+g9=X)4>+meKKX<m'
        '3X@OK>J{u|MkH$#1g!*8r@EuJ@(>DQ^N@HH7xRGqoCuG#bs3z1DM;P0|F|Y@dVnoh{}q*LT=`uF9_Qh)Bh-KLF{aSF(MsMK5I<R+'
        'p-OJ1Q~Lh`3Dxc5^m&0aFVEiH-dqs!sr9I`t@*Cz#$AykP`8q3^(jFek5cGb9y>hkrF1Q*IoRdcuMSZk8y4YiKOewwm9YZYcLoYi'
        'DjBvLKEybQ8mGd!;4_e&cVut^q$uA;@zI{>E~?6$jk`&&qaJMXBl?~`#IOlsrf83tZN{tgglEJeOA({x2&d84b}I$QqhlfLjwfJJ'
        'Dw)g=6Z-Il7pcv6o&FKSLYfeQdnk~|!dg~N{$%eU;(b|h0!wF_X%VPVKv2|_=mThy(m>miDvV)M`XX4RIZpo09_}&%gS6FD&U$H5'
        'k5JhYjeSJk%J>q_Ezso%XlFW9=&^<Jjac;M!QmvvU}I>H)Tt&A@-o+@Du4X5%;l8{$^^e8XCAuw49&t7LKT&Rlj7EB01IGoSenQP'
        'Ma&-l6IgA1?_ZFjVie{z_cPl>TK$7)C+zxlA8a0g8zZ&f0@sA$u0#166g|CH+?`_osXu)1pf^1F@$>>)c%+ms!v?}fUWp%?gs$E|'
        'QLjA{u^)_Lwj*F#+0-5P+cg(FYX2As$YS6C^9#X_LX?y%#9VgP<@mvs!l^TZW2Ug?O~EXPupiXA-r9*WILP4jj*f6{jd$BkB`ZL('
        'hLyaigMk%X6%!IId@G?GiB(ZB4yRqABpxDA4o7+GKTm#s7-r8P#^1qT5JB|ENwda~Dj~P7g_TmCH4K@Huke1C{-71)*P<Enr)4?l'
        '$N%p2B162;KKtPCd}!eKoskdDJJ5yYdFH`;CI5IM2L%U47DpD_Kn4iWb5gInr^BYi_?bRK*<(Q2C^c0+yp=-O1ooon5aEN%O5PjT'
        'OxKX}r48=AOQV*-EY$HOm<#i{315}_{^=D4!)ycGzb8m+(@bXH!Ht>7=2(^3l&WX`sJS5xMzAMQF~y^OCsm%Z#he?u;2wpifxGiA'
        'Nb@1<x3{@y$cDh<b~N}ZaM3LeN<)pIK(7E~CReya1t5j^Q!T2S6edfi2&41P3$c*Vhn8EvcBU<&rdkx(I;Ya~jIEj_X>9a$D!fo<'
        '-48g+WimyNK)j?SP(w|gb!|RGHg_YDB0nzG+}1>PfLWS9q)wJeI-ZY7vJRsZHyhsc)H3X8r^`E9grtTF6drhB^0I_?RZ^2FOfpF1'
        '&x*y&1BQWqq!41U|8b;dWJk~QUv5WEIy@A}VHej_S=14+O`cSePJ10*r>tf>QW+bd2LyLgz!YviE_BIZIk7wFJrToE%Tryi)JDj`'
        'k!n-VN@=t}t8v7nTQtO_uFCNHC>>Xk_5bYQ^UV<g&#Eg}88Xpk)eY_SywGmd7djkZN=N}4zNvRvPIcdxJLLzsSKL6EzsAs&DBuKZ'
        'pJM5&wJPK3PW<lz)m$7>^m8Q<|I1I6e^1IDplI1q5BJYa0<7UcvJV|$(}M<%UdT=aE6?s$KPH>|5R$s4WHDXpN(ybPqBE0iyU7e('
        '*o1(pPx0e|XtL*I)JMW|lN_*eR62No#tz*e(?$=~;MtyLje=sGf{RU$VWFhI<Pa=22O{nd5uz1NlUJzS9<<{FcyZ?(SS_RYBMl#y'
        ';SN9b?NB(<>n&_ZKydp=#$xu}^LK&+=@#jn*ruWl^<#{K!*;DLzwX&o=yOTkiAy7DtJCla4)K2+Li#L-5oFR1(2zosxFa^Nlec`8'
        'Q79tYbfqZ^>`*fWi-6-8NX;0tJf36PB>d&>(aU~pJh}HdQhqE7;i~-dlE)CaBR=zd7>f&RNG=hI>WO$+<?)hlv*uR(RFwP!qgZ~`'
        'h!7f@TSHOo`;vjp^fAonsz@f<6*VVXg0M&(fKwh&9}%RcjHO}n%E^lU*I%1168q?YUjF(~{=cG=3fS*ox4|q77q6*NTNkm<JOl@H'
        'IgZNX-Ro@?N95%GVD#2A>QlTis=FBY>Yz6SPw;H4%qG6z7{`!Vo$@}^SXP{vFfmd5A&>1VvtAl|CW?>O3_&2NsC$rKy$r@lU*`au'
        'iN$Nm{y#GTvTCVq^%3zTXN-5EH5Pc;Tbp2@v2q;q4zkOLK)&<zt@ub5Hg%hJ<t5D)W`xYm9-}8R&aT{S=TBN)qDij+_LR^eHY3ig'
        ';?5*&XU_{@m17OI%K@as$5;1t@Si`>ECsCW+jR*`RnAt$jgO(!)UcVI0e0C*gbUpC=l8z!krkxTT9yhMPa)#bh$;&uRqaJfEKvoW'
        '@XI=N+W_O(zWG|(p{QGaKa5b=u~Y6A0{83C*;}<(&W~);s#eurFbw^#&ng0*;e~7!y9x?C^{nFQbnW2TJqlBo@i+SGhS8<}G7m0<'
        '$&^9nPIa7u(6cI@7p!fIUV~yw%`K_xJJZSdO;zC}ya8Vq%?upYv|Ojt2(6h<YXv0tW;_6w=fEqtQlg(7)=m9lLk+t#z`*lr>I-F5'
        '`B=_Mf<#jB4^4cV5Osmc`x4`_C|D)3)ew)<H=o%DAP6uy1O`fo+sb701t^tD<2!ho#DDHvX|{~Dj~tuK!Ijyx37DrT36sh17B3X`'
        '988%-B(?hx@D>;pFAjULGzxx0uX<$GQ-T$HjPV9Kx~^ro7#E<t#?y@Q#lk_n<}rd$D~J0SmB7P<w2xRAEgdn7@QZC#t7Kd;LP&Or'
        'vdBR}(-8>3wm^5*^R5OO@9W-po1;%@td;b1KOGABMi}i}a(rM^Aj?arH*>9FRea8s)ENKF(%DAPG_q?@GuhD#T8o$em8caH0mStd'
        '!F=7I-0H8MCA(H6g9G!F_;T~&q|^wrbkM1ck<vAhW+B4~Z9~Q%dhoc@y<aD38&#Ab)f%h2L`Hg@)#C1QD8>Ai?>#E;q8eB}MVn!v'
        'f4+h*0DxW>^Ov5)?Oa(=v|M}RWV=&PYxsa;KXC)k(O~n9z2xL=;6ptNZaLm%xnmzfaT-Lvg_`$^zv=G6E&70baeHlR8^YlE7&6dm'
        'UK!AI?P~M}DZ<h&$&ds5u!_?Vy=L2QN?MR=h2j8{)@-X~jE{?-2(wYRB|ZDG_rvsI_YKu#ZytfS!8V@Ks&6gPah7}R`=CSXG=l}3'
        'd7p~yA~@0gJQRAylUE-{8wtL8o3oHoW|TXNyp`Iu!T6SRN<GFXG~vh1qz72Nw9lZ|<WHtm@d&WOg)D-|-4WeOJuhz;aQpV6nV++$'
        'zA_Cj>sS=JX_iXgrKWRcHUkZgW;OE@Su3~Cv`t)QE2wA}T}Q_s0^gv_dlYBuyfn1u31%uyveg5?I}w2(GihB{B*T2^eudY^4%Iks'
        ';n=(F7CS+)-eGpcez>I+p;F_m1IQ|a>d#eNsyS?Roz;ke{Ropmy+fQ$F*R4%(HSJWJXM$w3M<{N%newj^3&Q9luad)OZP#19N_v9'
        '^X!cH0gN&3JkDCLDknUmf}!fC3+@<iscObunK6>`#GPTG`s^NMrBkd-{<74)x3NqT_jpX^8p858{~Fk_9206MnMIF|v8;=UX=}T_'
        '%hCdgk2CSf;ODGsBGTQ1g%|ek)|@Hny5=hhH3v7ip$*?;x_GLx_g4Qiwv|yV|4z>k-pg%p1>B$c#yoRbm6;`Yd@g+Kn43DXywMwD'
        'YZ(N6?$6!tvGlae0eKL!$;6T>9pKGv!OO<(x@Dzt=NWt)hd^iBs-qX4u`lVUz<kC4q)&+59Q-11=dMdT&yngdHvYG)zXkoq%4R7I'
        'y$h1Tp2Mc4JLbh68NjikXM9xOFs|cUSox4@OHYBNb490tKBXj*g@;FMy=szWSPdJ&h-Dt=`uJCDD`SaTLi^-bq`SWM9wed*CA{t^'
        '?_`O}#*d#Ef$H1W6HACA964sxT(sXLURBF8%V74Z=73oXRj2+W%&cj(Jw;559OLF3-TM?H$32F%HRT~81X3ytcL*R7&X?K58GgRW'
        'tR@|W8_5n@jUN@wUExc97M}#0Q8}GfmY4VM%`LJ7N3w8FwT*T{6Iu%WCm>;+@4S*jE6}UivlfFCHZvr&nFx6=4X2Y!TXtlD=pqO}'
        '=dke5Ugh>y<WfSH8|E~%;3*V(d7TJwoNKGoF7ZA*VAuHJfpjP_^Rl_)QamUfHv6~lVT0W(IDXjsMY&PTR2nlFk#4+)5)NsuxDvR6'
        '<X@Phhw)?MZ#sIh^>c*q=4B?B2{Ky(0hU7Bc*6+y<suN9P@1CiGJH9_+18C}6teI3(U+a2f8)oa%6Oo&2$N%~n=%ll8aoDm)>N6M'
        'fpxFaqaXPNuQ^V%0`#fO7x17CSKGqTb-~+7fq=~72b^TL$`79LZd1!(U>9wqcDU4-kX7^xR+W+WW70YW^L^Z8o39Z{Tbi^wLD;bq'
        'UqcJFR#+QORHj{-5&Pvz%onnrnm2!-wK;BhZ0HvZXu)pZ>lRs>iXUx$+5zB5M6{ao#s6mNehs~bw?i#N72%^5Di5A-2lpdS!@Otb'
        '_oZ!R!W`NCk*{0CJEh5fQ}`t!AWW&fcS(|FEMxO5beN`?Z|M^uj-4df8{Nx)j-f^`Y^n-0FD0{{qTaMjqU?_g8xQI{M5#bDU1$Y&'
        'LQssUf~=5+5>mcpdqZrOXZq?<*_|B3C=OtAf3_dR6_CGmP#W<pc&WGE?}JEMqLM&~<ks_M=GXxztfndOR4jsJ;0$eCMN}WigPKN='
        '`7(;v&W@+T?$&6iLYSP(BaK=(sed6ncN{2M`0RwFkTnsVpgrB@;B*lC6hKtQR|TJ_^1aX?cGHEpE1iNnBnAN8$<(zSPB-<MqcK=('
        'R*}xk<KJ37;*fH?E0|VzS!GQ!WYjZd6&!w+&z!j^V;%lh(9-X~80ck}Ni<k@D{QQas-drt9q7&`GB6!30zX@9>QLi`Zv#j>DB{S!'
        '-Jnm0iZ@5>5%z$hO9)jU1VQKTW#2lri*<3o#M8yG!`LDH0vs98MRkhwX;vr2)#go`cwWp>Uuu=3y#LuSUi)_qp1351lAd5vsyEkc'
        'Qo5TQFoGYc%#iWOB*O<9`{JZzW&l;kU**=x__5CU;(+wJWkS1>o|Hut9v&h-kQBp*YZMAXWKj6p?lrk;+S-T+8mgPKRv3LQ3EH|4'
        '!-#!;hL5y?4j&j%=(_%KT#kFTll%3iL}+po6BKSure|#?f&7-fxJ-}?EVkz6mA)fDw5V-q3l_c#0XmF*I7Ib4^Y>s_ukLoxA4|0{'
        '_LF3ZSDCZo>nn{zgb>4v`3@eL+xNg)))d`yGzyh<4{HIKul@$pAbW^dAi=Sp9eOdCN8ZTab0FBA1HXFmit^asA5Bkzu*Y+ecp(u='
        '4i-tA?l^b!yljeic4*_HIaZs+d<`JTf^S$xm>DK%zc;d?iS&J)aLs$RqAGALGM(eJ09V5ib&Q@Zuo9+O<Fs8xQ2qA`Kj{OT=bd@@'
        '$O;NoYpwrk{%uo+s<?{=-0{M}$zv_fA3q)ln;#iEh+Ld#>%Ni3q<PYaz`PD`Upcc5XGw<Z2<l8F!MtJqry=c0Lzv}a#)TcS4xu)x'
        'I=UfW<GU~C<f%K2JSW}1h0Wgb#Qch&1)I=sfIXh7{{ol4kmlfTO>ncyRo2bSiMAYNnnM1jA&N(O@|)YTP3rMkVGj=xMa#{PWOxSE'
        '(z0}M$Akqbnu8BITA<^34J_`}i|6yPa#c4tyhnJ!uf82jgamu+u@udjdh0-p#47*UCND;m5V`;#m9ID256{w^7#a%55u!(n`tzwy'
        '-Zd^I_s&Yu)oX*;U|LpM$V5pr;G1?1O7u%3<hn$Q8Quv`U`4N!q61-AyWAzC+ve{1i8hkBYa|OM^ohmLV6UU+Hk(cNPSZqVcgsFj'
        'v)22<<V&*SmVw<SP$7g;@R<F=d0)iqrmhWqc2#m2Mo~`6AA=%e2RqpUWqWk}xPm#6134-LsC$sf8BASW$GJoNmNhUBF}%Ow6Tc=e'
        '%+z)9t8TN=1DCp+_?Q_aq%LI7V2j=nkw2sWe?3=yF8?oR31(?}o3aKC`QLR$pFuGT`~J#I<BWj`0h9x^+Grj&R>c8+w`RyTnc*9T'
        'E^ruC@iGnZa=69Uo{2~jU}(9C?Yn<u`Ka%lQ=e3U@8#|j*HGAgL8aW&cpa-eu9InC4LpM*hz{{~DI$68%Z^FoLhv0vuVCMsm8MBg'
        'mlWew1D}R8JiT;XDK9+FG_#It)wG1LIIXZQ+*J5{AO$H_At2@obyB?z3e+)*=0OxOw_L;`(aX;kZqy_@`yQ^u)r;=V%+4pnaBlQg'
        '_qgG-in7F}qGRfQY9o<3(Kju2*9V97Sq?2D-@y4z7f4cnnw<~o1ilb6oE|ONlDCE!M0UWf1F`i)LRQ0$A=DE)l=lY3mqn8GJWQ5a'
        'y$&%lX6r4`H0Ve&N5Tbh=UE2PM9~C~(<ju-isSzBisl|xQKpqU>(DvA^PYQG9!Kvnt5>Y!?jpRnV(jQqC;*GRmeV30qG##FD|H?-'
        'kEQ#pEwj|DMHEC(IU&A=1%VrM4$%++R)0M#M~5AbKtQ&2-GcT2TBkYP`Q&!}J~_t(whef1ut%LgXS3$8uQ9t<=h)G{yX$<G`#1M4'
        'Bpf7+<vaQBmTS9|d5KVV_2v3A>XxhLgVVajtiGgRRr1TtLF_ikuy&7@K^|egE-xe%@;G!>FE@s&DwT3EW~S`hD?fIh8Dz4*qLgdw'
        'CQ~&8xytO>|KWEQTb9??U)iy0!72~F*=(^6o;71lb9o>Fc#fX7Pn*L}l5SD(tZCk+DhvAj>5~2QlhFW^!iAvlJ3%7=a8SK>&x!?T'
        'Fio13?sy<Gl+qc*u5ucIWarMgqH24`2n-LB?uy0DgDr`;Y=`U_5tjiR4mjmCXVt5JA}HdYOk4xnE91<zh_xkXwjubj1ljL_C~_VJ'
        'cFr~To&g3tNm`Z3f|VQ3`2Yi#y4W3BanL=Dl7HR+sVL<9J6OG##gzQ5G#u2_@Q;`fL(TvI2WIji=fvPw3Pdx1_1N!^c-!NiQH=&T'
        '8r9ri3@P$1z@}s!ydJSIWhgBa4q^S>4i*^M>f;(<ZoB@et)P*%eswj&1t7XNl?)=SI588qO&$waOfGl>)oQ(M)uhjp@NM(tm~3sG'
        '@>*1q3q9sAZXZjzq+^ibC5+-=^r4Fr-5UD946D-YpUf~YLiY3e&)ulR{9z}QkmH?bm74h1_DaDIzg?G6DI-rs(Aiu<A;o-PFy`^Q'
        'Q(AG2z&#TfJX*OLNo(I|pBaam;Ak4dPZuC_QZnW_dbMi?bd}>UvxUnh#91)-Y@srUgx~^lwk<yh-bMbBaE)dtF!B*b+<%7%6&eEn'
        '%8_zg^}nn!keAw5nV-=$t(OLO`dhi6cDc8m^JcIQm)T+gB}=>iMKplZducp_WIg@)tZB&iioFy?+ey@Z7OW39O;qJTrwg@0!3{Zm'
        'i|Vbm29Pyfp8{&<Bp@VJT2q*&{L7=dqSHkr0d&O&b1HPNIi!Hx;k>0q1x5^DEm_oGx@lj)MCZA&#FLm(IDdP*`@Vzu6>v0mo=(Dh'
        '<<Wf|qGsW&sx6ySIl*9(uaTy(*U~lR=gnw0Ly&Y31h-CYx|5b7yu=?{m(4jf5=Kj`_|z@L*S60vh2gP$bZoAKC!iPk&+Iqa=ft9l'
        '7cIo5xe*;6)ehO2^=Z0}nsUu$%DgpT@X1V-kBZ%vbt;pLkgp8hG%E_9l$V(|3G^;EW$P1>@e;LAb5cNMVEWN{#&F9c&O*zB1g*b`'
        '9z$RU5l{^<DaUUl>G4VF_Pk<3_x<;@FcOHOd%awRPW+GnMb<B?fkBC&9*@$Qky8Tz^+;p{N(AH;Q+R=6$QsI9*~D+SWBT8UPl*au'
        '0F6%Df3zSI?a%8ZhF1vVvEu-{;uaa&X8xxUq!7k0AQWpL8%R3=cTYpaD&*zIkoM4cj7|m(h#?@3R;<pJS{X|#oEpm&@+X5zsrORK'
        'iMP`ar97Tu=}ux5?=GRRAd0k#@g5ZWweiRT4GD<7SR<rr9UtN1kgDbbG0W2ie>~PqBgOZ#8(%X^7I)Ugaa?LY!XdHNN&3D8R+mMF'
        'Z9wSuA3nx8bX2xIJXtSf9}^b3N&a8|KsD*Zw>^mU#SgjIe=Oq$11Qf>Km5-@1?z0}J*f~*vvCcRUKt7Bb^V<!MyWWoE2>!)IGs7@'
        '>#J-|ur?Fd%1(>$feBBttr{B8VcYAFK{^q_O&xF#xuSzCF|@aG3FIQ;!Dxlsw5G9GPI&9ix|UrwN-&hK<72q~_2DBR&n|1oo5;Bt'
        'Lmdx#cAtXJB13QPsE(&c8vw6*tJDj7ndvNs!8^&#Y@+vm=gg$|KHp3uwg!rXw(t#y9)=Gy%V|Qp_fFG1q<MAHHk@pr=XFo8k@WIP'
        '?^idn0HxZuD()JY-Zp2PO9C_7_(E;tostGry-my98mqBx-d;KKw9p9iz50GodNkd$UjKZ*+JC*fouu4U*!PS=gwoQ7*KTl*ZiY%@'
        '<}4TQQUj?z2um(#5A8d@Qn#a@6;0&=A7g&xn)sP~_I^;Jc^f}OCsH~s*)I`%Jy!DN-xG&a?&!ZagZ-sXZXhj1>Q7&Q@8%1?uMdhU'
        '5@XP?e$id02tCWF;MR>(=PG!b)0!}A(j-k$QXWWO*Nd)^K$J|2A?2FML1f0`@Qwc~dSKKVL9t~H-^ABB?co+<;jIqbQxKB;rNWWv'
        '^lWwwF~B?^>+sSl$iGJTE7rXj@8<qOpA02l#}b}q+i8JT`~faEjL0)G8m21!;{jZe<wT`m&D5sLNg2QD>c_b1>S;Ctxs`D7^qH^O'
        'MN4{KOWAMp4EH5gxNt28x~$*h%N3O)UnuOy0I}7=@Xn^9_{@41L*f;U=hT-fycpg-_Qv<Z0(Bo1k~P`E7|)1_H`rAPh2No$8!Cut'
        'bi*n2t9I=OD?sW4s2>|A=9l&~xYhNBsl{4FJNeYsqB+;JcN||2SKG|y4l;949b8Aaj6|Wcw9!rHcdQ;!_N)JcG1F~zL(gB(V5jdb'
        '`e<72FCGZC!H-@wxtrUvWVr~C0O--$nIx;TH(Krf6t_1T;hBMt>-YNk)F+PHWCFl@7@}S=P6}3K$k?Ybr7w=x8Eqs8&Hgp0h<znK'
        'er2t1-+Q(ow+#DjgkukP7OU2tG4Y~dv_B1aJbZYa^Uwdda-g0?j9Oc&5r?w+Ozw^JiMEo<6Cf}eL{>;tbWb2y-hI!G($U&s9`_D+'
        'n-6VA_wqq9M+C@obaf(zW!CM@t)RrhfNJ2ydr3Z3NP^c}djjw~d7#9ZCY|ehIlQE(V&H!yCRq8{Q!H{Dckc#E9b;=?LDY#)m9#(d'
        'np-KJPMJAQ_i^Qd>?R7cpAGu};z(twjuv~w?n9|-ekv7@x0A&j1eQ^4Q_D#?BFk98zWNX~`lY?XxW{BBl+@P=mL}oNmx4iyP!iNY'
        'S!(p2WW4;5CGTmzT%g!nrDOc0z41C>r7(e_RWtv)#8Wo}`;IHUaoG~cNh-)QNQHCP5QaY^*PvqlU~vUt7-&yV{=*}-I;Q!5>9sr8'
        '5&V(phA7zd;U(qA1;hC(fKih}kcORZTxtyzT{!E2ogM6j@O=W+3+CdX2m<s7!BYIzu3J{38$3X>v7e$v$L%=zk1SnR?k1!qUN3mo'
        '*i10-*?sj8qJcBpD(&5B>`AWG3Z!Qo3(~VGr;dmS$!Wg09hNF9j{@QBl2Eabrmxwbc`Cq+nT#(Mbx$Ycpz;+^vwHc+Cd5(7*Rgow'
        '@eg_!z4nTI4#e{$RPOj((V?+Fs<R638Yq!YykxKKkB@G4<tpb6JPTE6r1^vmc-DZeArwZe6dCHvP5m``ONv|0r?oxB@OD-FET)2;'
        'h)G(U<AzT?PMdCmIBu<`0Kl)~a|R`jIHz@3mQg6yo&;LCAEoYhH>4r`m>)o+W<?$Qk`DZQ&23<dLI%R=lBzX1epXbQl3J9pVtDDe'
        ')jTv+w4CHi>F)0!$Yt3?dIPn=f*=7@$kM(#L7s`P73Y|MxXVE}3Ul9;hDP_?bogz?VWBfJ&F?I(V+lIC!uPobjwXC}r4z}nQ{FBz'
        '1hHwRG#{$7F7mdO$bm&Ymsm~8?c~*@z8N$b4F?wL(i{=UsXi*H)ntF@V<2%zcVw|z6BL>uf@OYl^)Oon<dnr(j#_%|*83XWM`wC}'
        '&lA+7{&Be1!}Ztrf3??XmKcRH&;3ng#b1PG(+0`_Ng>hP^yvrW08Ebud*4nn7rv7+O5C$X4guJ}hKu!X^f%?<{pcyfEI?hbwD+GW'
        'vcBiCNCvb+*92m}NgNjVRhfewTtXVptwZGF2i7Xm{qqZh^1``CJDa5TQmuB)D5)p`WBX)UWka=8<~PrEC8_8Fi&;Vjy+XbPx!Nej'
        '#V>)uL_RC_<2p5EvN<(X)l<9&q1jKWWedvB@SoK`LS=(ay^WnL&_ugdMaUH30=ESiIeDy;=~G>X(=53oAL3wbYruWvzZxb)N!a5$'
        'hJt2FP*~)7dg1h3`avhg`qa*;5ts^>OkWrb$460V!8})0Mms(`CrMa}TCP|=WXKOS>Y9pX6u-%O5NmJIF_wj>)XV?4=1E0gV?p9c'
        'DaT|OR`UfN{6$+3(W3kT<+KLwJ$jGou^;ix<+HLkL0doN4a_+x_<pD?>K{{i2GQg&QYM)9c{e?;l-rrf6=NF(&D;MENuO($OuE`n'
        '$qu%np%>FJgtYKeLBaSf3E>M)nltZ(s-WG9`(vUB^u%8etjqahfvYHC4}kL}d$l9j7&i8TD6Yt~5WEK2&b(w0oPM#ntP@oCqZ9_r'
        '<(sZR1#L*kt`GeJ+o>N?TZ*rKg<nTa5WpAA#hhca1n?Iiav#!&-;_{SA|>)`TCCE#X@?5H5ltZCQXL|h5rkCOYkU1A9ss$-&%$Z!'
        '40~&NsmVs&`XtC5>16+-4zk{onn+T2Wpc=RS3iJVpIp7@z?>QA4{q)Wfdl4K*5y{hazkMkbz3of1-)&O$d}c>l4NUi0DB^%I-}zz'
        'CSFT1y0dwF5-D`sKZ_p@4cA}6IQ8Yk4qr_T^HJpm8V=EI1}M%he|F9y*u;Ryl}+J&x4fU(9y8Rn2<SADsKsJlNR`2_lVz)s<!}3L'
        '(B$8R;;9VZ^V1z)r&DaTYZ3=}9Bzg&UPEENC}qw*@-Bef`puy6>QjpPPl@x`G>fC<B96%)e+8u6@tHEbc%Kjg7tLhBg?8k)C!AL2'
        'FQAQ(??I0kfo%yPzEq8gMIqPL4a8Ikg?5x)(&No?GLb;C@JI8O@z8x*2fRL|`ee$UXN)wo0OiCM0}hquZRrMt?dL!e=@bNVupN1E'
        '%G41pSVGL~1@&zj8J;~DL9=U-x*B|f<Kq-C4t!VT@R+J0rCUdzZcH~=?tg47)-p30aI+9TW7Qi&Tmm<m#^szlOD7Sv9h)^v)0rXc'
        'TOsiM*&P6Z<zeAqOJRt=bGnN<OP8!4M9SusFTZOd6^V7qT7YShJ&2as*IJSh5o!YZbD;W=A1ca)^DBgm8Pr$@YgT@SO$1mvOx?eI'
        '^hLCkybdrK$zl7)%1X+=mP|qEdU|{>QFlDEr30HFH{?cpPC^byxd&rr@02KA_}<bed5j!C3W+O68my`|ozhlAXr1@lt7kh_LU7+@'
        'Pg9Sr>q8}OD6pDPUp_Om4|V5QK6b`NiqBD?@@^Ag!+&P^$vs~}0CA$(Rie+?`Dv~XP$jralpqXw;4ZPK_7Pb09pD2fT^J^GcV4N;'
        'KQJMB`wY(#Rf6C!n_7*kmrk9DvlDyCzLwnh0NHdt(hMX35X>e~?8GtGb!L!H(YB>6K-b4&$iTZKWD#R_%B0$&;mO*eW$%LhuPYtQ'
        '0Y~P9<8-(b$t33WKVy-%1u-STPD&a_4s^70BC(u~qH+Qgb*ad1(DY>|Tct-xm_mGX<2{`wdxZBdQn=X>9hH=O&`BcAJ})@KR3FQ7'
        'W<hhKd(zD^bqF(avJm=o`2eX;3r4bLh)4^UoQMTQ{8asH;N9hOR=i!##ls#>nEwZ5_t0Z{8(rS8vJ5G|T23L$>y;~z1{1Owz3s|d'
        '#xY!Uv-0XEj3Ie9qjxN=;{)jQ^{mq3xmp2WPYep05;yydT4JE$(r%nMU)S4UDt&n0YAUAczJg6U7y;m!L6;aw1G>E9L%yssC9p2$'
        ')F>D%Lo>I*mm7?*;0k*in*8BVmnduTA3%BEQUSbLf+Ym(Qk}u+r{%Xfwq1yl@45g7CO(La*`E(Xa&23J___ob*c~UgVp&c+#5f$4'
        '8vh<U9;I0EnZ>I{OlU%CAwBv;c<yMCUNh5O9WdeKf>H{yRJs3j9&%<Q`VF-5tf*cxwPquG#E$8-s}=}U%IdyP@OhA}uY|Mn>BPNz'
        'n3G)uZ9kB88}ysQ?Cq1h@VLnW?Nn~`KsPv~jy|Gx-eg$T%LX!eHqCM1QL5>F>>OQ<e9q*n2Xby~XJ7TK5>9_h;|ZwLI7u|6kK`Q3'
        ')A>U%jQK_lYP55EAMV=Rh|gat#z}B+GEk1a(tGh@hnWcJAm<@P`Q7rDEDsq-mi3C#Y-jnv-O9<K?=2Xs1?8mGTm1aDBv7k3r4m#E'
        'bB73!7N4LRA12E2yY=2|H!*I@iK+HWK@FEXt-@492-A-cHT6K>hmD6o8?$hRU4DAM&Ezn`TXsO~)aI1e;sKTTIp>=_a&g`P*&X)t'
        '*3P~&{CxA(xfSwH{<8tMK*?WN(mF1|V1@8MJ)A16xoS@@g&FPbJK_Kmt)sUw3%?*8F*Emrj;>?}yZ+=K{LC{n%!yFNjee06!@aLn'
        'B}5RId7|UMrp=*D0iT(IZKr&~FshuCj}c!K`md(#ZcR95FI@h<qElQkDtp2ZTt1d<+pSV$*K8-~ShdDMNNAW)U7*H$2(y`4P!s+f'
        '*v66^H9l*1Q*@A)xPR~CNQOq89;s%cNh0%Xwir%@(6YKwMii446ubBa^@5Xjb>N2);8Uu{1&9Yy<(1nZD43QO$ewFMTAUqghkeHO'
        'I(ewn%3V}`v#B09vB?(M5xEUfk75T`W9uvjnG7|2GU_xb*9X#1ObRPrmw&-{acUPP4xC3NUFMvo&eY<tmbv&o$Sl4j`&8tifuO*^'
        '<O}p(k}WtgA_{rJ4^Z)~AC7TYr5%>PajQ?gmvY`teAXDyv%uRQwa{F@!bl?91X`H@IM$!`xxxvMM=xRfiXgH<g8}%9$3M1hV1*-C'
        'q%Kf;d5D<JeeOlIF{#eDcxcF1VrF>`Nv=3AsF)*Tsf^vnqITnF?w?6g7Z=XBr#I~X4&Zn@Lwv8@v^J=#D~LZimKM^b<beU)i(KbE'
        '4`65W`PaBz{kbNc25FbZ&+n%jIO+lo%U7akSlKhmZmNtTIX>h)JF@GCmEafXgZQnxgc~&NP2qAs1(xV$z$6^%_LT%PndXantQmi{'
        'TS3<epd-zw*eMm!u~)3hRwEAJ6Pe#LuS|!+Y28LA|HWoNexXk(3P=TZXpiO%oaU_JGDdylRFl9d$C-NmWIIA5$l_vJi2)*9@>aFH'
        '$_T~;zQ;_}999SRGwK_Le(OKh<uwfBHnvcNNxA?R2|1xxaiV#J)#0p8Zdar-`3TY}O+W-`s3A>>ao1h?jUp{C0`@Jyfc{WTUlKs*'
        'SdTD~s$t@siD-&e@a)MdK0jvDYWKS3o%-Qm(>XTr<nzfTjdyIgjQMokLtzDv;^}Ku)jBqOP0#u`>W?<<kD$E&&U+F~%^7`J3d*(2'
        'sp`|-yhb~VST##}00<CTUKg+Q#f)YkH5Z*VhP@gf!w}FC)O8y8zsGwPyqllUGxiyiU<Cbcwh(lL*_`}Se|kbs`T$bLvxe5)%@BCg'
        '$&?l(0=6(au=Fa6^MCQ0)$InfB%Aa9MQBIXMGC70$qy&kyqG_ePM$=|GV{!t-UQ`OboMXs;&|BFpHiubZPGb-<^>2cS*W6sm)t*O'
        '=zEwQj^;B7Jd`D&*g4m=_|<L)LfohQIUy_tLzR`Je>NXAs$H!kd_e6QF_s3#>~pc{a4Eu|c#o%Qad2jy5DygB<YB%jniBO3I%>%='
        'tH)prxD11o+NKr)DzZGlq9NcU$lx6`rOlK)0(onteO#YQM&^=^TF%WXqZG!a$s`-Z8oS$?sDHl)*v)*oRv<h0Qv#_78Uvt@-WL_d'
        'h?NUuMES=418?&LEf}hI$fzZ0Jnr!Ng|<oTiPlkEKqU*A-(=fEPLh#aUp#yYj}UhFHRkx~VMtaV(<l7uNEGXT=$v7}Qg=wIY2v7p'
        's>$gGGHW7u;<6a;&VWc{L4{T45D)sWa`js(Qi+6M)!_XBxfvSUMPX0(Sjjz7ke=K0YRIsSCfI*zX{oe3U|aR2B+KkxsRsk6fDk_&'
        '%)D1LhSvQ`d%sJzBOE1|Tnf7fVSUIIaH2+&W4?>iJ55T%DgiCEhck(PmcCGZsg_Q)ti&{xtoa~^xPLYcp-Rp|eC;h-*%Xa&U&Gd='
        'oX+LvAaC?e6z7L31*-CZw@=#;%5HjUw8;x8!|GBN6q9Soky@8;&2YZrw7Dp*A61(sFHI^MIY@~oJ0}1`Bg!=9<kw!dWnn3u<o3iH'
        'Ly7fEfA?um^o%ayz)zwg*&+22{eSjOw?%S{Hb(`@<DB!NU#Xc=Z+L`lJc?3j=^nFh(xR~a6$*ze6L0B(PKEfVyyKG&hwuXsxeP;|'
        '4cU{6@~=yk3iHlteCTv0Kf7*+1aJ^C<gbYA+^l><8+>n9WEH{AP0Sd4;#9(T#Ca;vnk&W=ekO>Tt>czt)$9L}RxNm5iaO2fHzxxD'
        '7Zcy^k&PGDC!|lCT}(mi&0;=0U&I~n6ikjATZO&;rp2IlkV4Xm)G~u`txw3^mTfF~8rbBEr8f3-fzE3oKpR`tKa7iFZotKsDYCEK'
        'r~Psa*R8g@IP!8%OM|-E;c@XOr_vf3epj=z_SYd`*G-ZE!=^Tl-Di|#zp8jY#VKIjW)_a50;_WT9pThx`%;!EJ^25Y^2+Wu%dUHW'
        'HimwepelABY=p7}y>F%=lArYfxC+)Vx<Q|pW#si1hEAmPc_Wl|Zs(^)2UVW6mjG@1mjS?GA`GLP?gC8Vgp%(PIhZILLbe~5zZHBz'
        'G4#GHF9z%+`DPGbgS-k~wGf=3<ed4-QBdM6vE;&1L7+Q|6ifj+jz0Q*i5r!5r`$bi*hNGY6p2hMJ%%rJ6cPDCV%W*ue3gO7v&^fS'
        'UGN@!*2|;>2nB#FiGF`i6D8cQ4hGX&jJT+}L(Hwggm}@$IDMtbtl5^1u2z=u(fX|Qf+7~R;kTTaXrT{K0DDUfEC1+f^1+fW@2RyV'
        'SMd8DpRiH~3)G%E8)`0Q&E{XuIbl}@&(LF3{AKzql$^MOGBK02^(1#Fo+uR^XLDAEX=D0k(z8Jv&YP5A0U8Xr$nJ6S^L6z`uoJxc'
        '2v92EwC9RS3wfNZIl)S(HfzFgqx~PYVq?>SKz5y_0F@ittYp*hL)aGI)TWbeQ;SUcYV}HbF$p0L!@}FLbRHz~E^fJICLtK>{D}%y'
        'Ce)Rhug*2Uk6rWd4a{_FPnz+Fo$Gs`(|qA#VOY?Tc}LA?%bw5uz;-)*L61E^=ETwYs0@fP_E_*z_Y^d#&Xjqg@T8Coi6l+Ssnd}P'
        '4N!gwtQN@H`4<Jn$<ayU^4w4Aqr?(=3ub)S5BNYpB)QaD+gG%ZAt0%d*N1Y?10B)0xCZ|weQXhV(oeu?O<1t);<fr(L}?|Ejt!%^'
        'seQ=fV`+>Mq*n3jfBwR3hAaOvD6fyOqj`}{8QRxHyY}$l+yM4?TlSRX$|XL?lABRw6a8|<T#QI}LF3R2Q%h)Ysvx2r?fN9Mcp~{f'
        '{48@26iDtGCaFvMUw3fT10I=WKGCM#u%RTD4xrY7hOAc;z<FDm1d8jyfCHn(U&#oOLoTsba$l<bZ|pJS+Ro)ap`R0&i`T{ch`X$e'
        'gkVu?WU~F18cBB!_w8zL3ug4Up;XBAJyQE4`>6q%<TiT5tjTbr8h^*WCS5M`RTb(|iU1#OsF6=Os1<!2pV?Uroa(sDSEWxTY$V>7'
        'p{03C(u!ar|9PA{nlS3GjzUR>-}(uTyp}@DEyOBKl_BV*SmhZ6Az+_@QGw7vENo7uuZA+_0ou+c8gf6Nz0o9!lB5R#>hiH=)EQxp'
        'gBh}K+GLz3tx<}c8hz&8qNzgJ^9GLYME`S}1FdNUd$l(I5lG4|=RYofd9FQN<lp+f(Y<gZu1R@|Ps{v<yhR$(!l`O=8rY9S;f#Iz'
        'Zo18YFwYU&#tPlF`&<5%^za!+t#N1%v;tD%0);0FH$Cg_o*S$L<hZuJ8?gU}86`34qlwka`n6X$S^0!iByfFfH6%cNzL0=H+I>}N'
        'bM2Quj3Qmh#&q*WZ&h6~+gwPK>noe8_Wr(J7&szri}{7-t6-6UyRG7jFLMj(*V)zGhJZNfWR%7$*2u3us=IA04vv~n?_T3`XzzC*'
        'mWY5(h)U|yGcW9BuBJWr6mN$>H4QGD`equvdP2SkC)!|U#5R1~)jI`OYiOz=9ejq4SV0MC`5Y9ETjvmEif8RhR^J7jow1+4+Rv*0'
        'QQ3nI80J?FsIqn;I#Nf^%EMcc-EDz!zL0L{{UKbqbL6;oqoO>6N$3ETeUP9T_$kS+#vTX<{`YvU75uj>U}LyQN5SQWWQHR-%e%?+'
        '>?O=?fTQ~hHAG%6u31kz(+Y7EM8sLaB&b()5AHLarj4<(Rm81^efvHLjv&|-PvV<okTof)^Ga+S5f7q=1id2Il;RjZu10`onWbCq'
        'vY1y?(SD$$S7({6|K?N*_TI^~YAlc&g55RTzZkC!^TH+MY%k=YO*Kafr{9`(ct0$VBceoS<U6$%I^ItPF!%hB5-geTF}zY5Evm7k'
        'I}Cb9smi{Oy7JrmDjnSk&7V$isC}sz`P?z=Xr9LMe8KArT#8m@-{o5~*a#cCc7NM^`!XP_9(~{m7Dof$+UWxPb$Mn@P|GTY*I)2$'
        'jp+{92VyvDd7cVBl$Gu~RRzP=V(E8~V|VD0yu{Z85k-frp^DHw4qt0@MS=E!raL7kIT<iC)+z&5fK4)N99%9EUP3UumzZ?m;FZ_V'
        'O1mMr<qC84P7AHB{?6q<N)d>@Dhdpiach_LEs5T+H0tHO&lqITO<t9dGEqvg51;Zc!e%i+bgGIrB2{`7Biaetf%5QjtAe2>gL4e8'
        '-%px|_Mq%L0t)h-&fQN-gZN{13=uwnsH#zle&xQ(3(}jb&zufVB(}>4DW3pp3Mb~dc3)S8p%DN(MI0TA^Z~9}33&xBD8G(t9?S!Y'
        'cIEgPtct0VSNvBz)g(TxMU$)3O`tpj@-X{B`oIY+($<0rDC9>4@mh$&rSujjEimDLGI@Ym1UiBusn&cm0A+j4l6K>nzN>6-<MKl='
        '%3QJk*$U#F>;>1C;cfDpU?c!d>-(BFIf92(U0G?&w#j|wJ!6vMr}`}P4z({h3=aNn|IvBCaaB!X#hI~^z6|TY8o7WGjW&3SUJeNu'
        'quyvLBFxB)gSd{aZ8OKLPg4gtGGqFx*S>38(vNVrA*9s%<wu_9kNkD&QYnc>e3(>uh+U+8X<iccbSSE+nP<tVKtzOT-RRy>XIvgX'
        '?^Mv}zGxfYF5Zehc--y{DH5P1<<Ff_S*{{Jadb_KtlQ;^VzmR4?+Q<`ol2ZGSk@;LrwZf?L9<27d1RDeq%4(}7(-|q*!0eTW#2?!'
        'j3)ig`y%aDBR7*Jd6D%Cg^*?kf0S5wij__p(8;D53yDqJ%{N&SLu~hq+7mSc$o#95ZRPJiqsZ3MWD4wAgULHgmxr9{Z$q@jjK{m7'
        '%k51-kpDH#6%=l)#dO(@-!4t24mZtj$%PA**Z*|<HD|tf_@|hJH55keR?oC>ICG%E6_${_nGb>~0CjQmjxb?-4YE)YAbdUlW2q-&'
        'IMj=cVtj&UaH|{xL7IxVOf{A5hRZxQc~c~fu&@LgE|mB{QFSO7%vVN-;y>-3Pi^~&7{;?-o!oUEyYVp_mx&FP--_dSU@?P7WRO-R'
        'E&n$u%CG&{hA(oss`rxANWvpN@~FR@u2`>ER=TDy$U?RJ$mc4CB}*c@Q;v=GhzwqF*etd1=#Vb?uz4}^yPyaMf|rQX8xig!LH6e('
        'psgYxP8kkIu6XoGv;HGg>w8JzZn;`<c6DraE04k!q!<ug5}|-Ws=X!qGu6&}d4)jmlD1~ln8Rvs*-t7!-x8~AS~7C{*GJpN>@rNJ'
        '@W;P+bL?L)y`HA!z#u@=SBQ5{rbhS8G~QzsVGRYK?b}fyH%lW+=U&~XWomGq@MBl|mA;*qWY=D|w4B8iY%%(~V_k{lZmRuE;DR3G'
        'NPTQMkvg?us2dm4M269>&R$qaMOeby4T?*=5o03S&PXiMqw1rhb*{o-7AZ&%`%Tm8b+p}86Vdej0cAufy<t_AYIc^9A<JkvA}4mP'
        '-q^9%S_y3%m^1Zw6r^|94Ml>yJl*P6I40{cpY3jmxuG*yH-4w-D?#3<hU>GuxC9{rbB!qO`cc~OC;8Y}O(dFkj+gr$5yms<l61c^'
        '46y8jWFX#(ydPYcV=C)D|B}l5=$4MIRvZTVzcmU_Cbx7_%gtRj*ecCenGR>G<DmArS8W#lL%#HKrTkIwRs*qo>e?>xYCPgv-i{WJ'
        'mW>7n_$4)9dCcWA|4&EwVDd#&J(zUCaSl90LE9_=gG+>)+u?^l2%l@`)J28`nSZ+F>=FOCgP`l~PjX^Q8Ts2)wi*<7CJ;|960;E>'
        'Tq7dv-Lf!D1oS^DhDmY8n~CAPL}-KLqTzlN_uiQ}R!z3)<q<cus(7W>Z8Zm$mF3!xckfb|5bHJHW5`+i&pm=J<T;<YaxX&M07pd-'
        'jy92l?ORo58uifi<+Uy$h@Ad=^$9*BVV{{CfWI|4w?gVN`rvucwVy!qMOm|$&ANk&^8;k*;=4WDDjNl7Y}=E&20IdsVjRkgVqV0e'
        '-uq+_sB2w8gfdkn{D7LF?s~*%-rtF3G+0uN?1WsrHP~0M@xi_#?%F|bAy>-*J)dHy)QWaDYl{^1-DvPk8FQ3~Mx_JwMCv4%a!XDt'
        'XM7_50Vao+yL-&lE#0ca;%a5gTBNQCz2_@h#Oo*-34i=0FiUEac4rsJ^buyr7*vJw*342v?uA<hf+|;p1f)#o4D0~J$SNcH3VgAP'
        'vSb*5e^kMurP{tUH{?_;1>i_&KK^Yw#WUED^&NjLbRZT@wNOSe%wLQq3Q^MhL1#6cmLea=qbl$dKA?mNcymu7A$HiwE9bmaM_B)~'
        '!|Lv_#jM(h5Bb#o#nvwM={~+#d95(A1>~{CK%)t@iv5x!e&hh>HM7p}FR>@D#kkhec0AVYlylFZ*aLOB*pl#n8429qv7J3wf~)H~'
        'V9DJ_hXzty*9y;cHD<H%w4rERWfjT2W;7`;!1*Q%I~urH*a4Mf8$e<S){;%5S4#kTr`iguPjgjIFc%ai8J7PT(VRmlr)_yO&<#p>'
        '#I2_6`3tgld=D`F@_p$?3@(CZm|-TX+VQ0+|7{4|n|@Uk(A^imUslWp^}vIUP|gg`<3|GcZ4m9vUc11pRuG$cq64gz`IH9}(BjM_'
        ';VoynuxYLzHT+QzcN#J^8w{tOyK3AN_s^$7q#_!U^8>{c<gp(hZHK_iSt<Z0YUyP*gmLIuIFj4Z3>i23cM-teKSO$m^RDIjDkyE+'
        '!*bsN&Hq%VU_6AQhz9~wYiG}As!ggC{GKh-8|D<Rz~K$TcsSjbvImnWDEnJwH=R3gQ(xXo#MGV*?oa`!{!}-Ow;~$~97Bc4%aIr*'
        'jmhTKny~IEHx)drMIn$L^^SA`nAZWLjP;UJ^a26g!^B?shE@?D?kdSpB{kb5eOohNL&{aksO+j4v^zO(+4a6s>49%jdeTxT#kR`~'
        'JDfxs?0Z4N0i)S6!M64*=n)=HC3Fq032uLWIl-P#r~!>a>+zr$Yj7-4EtKP_c;%OVXjcn{J+xuQ@WPrgN^uo)c8w;9@&=&2WG}Lv'
        'KeliUC5QdEQ5h)5D#4EWU!ch6YyK2}G{ZE7$C+dU<*MLfQ83c9@3Q!VN+@WDki&Gq_}Im!>D~otqzs^l)u?2K-@sOod)END{et@-'
        '8rMK}aiz*X|LSAFJbRT<)F9U%{B02RkRPRTGP@K;58e$w$h=@ZtUEg}B_jkDB@vw<cv;`!M%7uH>P+B(rSueLxa;XZ2r<khRHH&Z'
        '9+jA)9xww#+*T#`d1j1|%}b^c%6C?l5wcSt&TnjodyKD)ya4l(TX9o{QcCM&@kFJ}JSdw2ABrs+r!O_e(t&=XmeHGdg&uy1$k<H&'
        'FB$LF@>#!70v?L*Gk#^#30Er7(2wB50Ea>xAuNt%!Sht#P21So9X`ZB9IfCZ7oi*M*zQaY=tJbqKbTO+L9#}<hsU|Q_l&3Tnn%lD'
        '>u^aceewvc;y=sH&->d9@VXYtAm9#%Vmc6>3zY_Nz9aa0j)yKE>(ln^^7Ps|Yz<^>(<#+-?r{An1`qMWkR{$UfOsH`H=Q$$6gv5`'
        ')~Qx|*t1Z2B=%&x?78fG6-R^IQ-F=X5b;SO!Jm5=q^wCjMN!|(g^uOg?uQ9a<ao@>OwZC5Dp?;@Yjog?03*VC+X{oJi6RVO7?{`M'
        '{qaDDs!t#M!(&#E(gGSPS$IZSxTVrW>RffA0F)NF6R>Z3=_~^<lfN~U^Z$zRLR(JFK*__#z7;=<dEYR3@N;vI7Q8Q6_<p}ru<l!g'
        'K~v*afsW|7C_rxEKw}>Hm&Udk)L_>^rXHjHLR?ask`V$pXti?LQ&o0Zoo)@I6qUT6<*)<MoRi~kyD+&}i$uvAA)acVPi@FG<-Wjo'
        'yq~6pyvi&Cn-RwLS!^bqf{;F}(iR8D8<*5F#y53eCf|_9I#F~eOnDZE>rkx-$-@>J;mzQiS1pfTCjTQaB|F++kZP{W9R~Ct<CE7$'
        'lnw0D@*p6)L8RLH7mz8>%pY^cLSwWUubVR1h-=DVi_l9Z{k3o%JMMOk4~EAy1j*^Yjm$r-$(_t2{j@8X8R8j;qvJUJJV$IfTc$1!'
        'dUI$lw$SH^XHaW-?jvQ)YOLIiWBDdeJOO`DBA0|pRi^@F?CfNmXv&~s^=+#MK4*}0c(V#(KwWlB!VoSeyO{~sRw$@3vA;FviD)2@'
        'x6kIEd6o6|AyN~*;|`%h4dS`D$L!5VI5UZh0C}SjqdB(17`*H!Sfn`c9ixCIwY@g{bgcK(ceA4FNYD&erOZr&Wm*(ie;YqYBA~YR'
        '7!D_)mQW(NRsqD!v7HM-(%6C;FFG51biTZ*Cw5~*H3ikMl4e)jr4=BG7q{(I_mhPC4_Ld6WpF*Ido@}eoUFQy>g2<a`kG>flZ7wn'
        'T_(_lRf^P-UN4t~%!EEY=cKV&6qSu3ZTJb}0=c-leDL)II=cuBLLHJrdid;im^Aspm+b&zAqv1KU4D)mvyAT#n%Q?70(gw4ck0nH'
        'F)BdCijvaO+<H6UlfkI2BBt<r3gM8U#AbT+CKk||ErRpom`}od0ExWvshlPhAgOx=v+jQ9FfS)V08UmtM6WFCslj6hblSoUy9Waa'
        'fL*qPQl?%QXmHy@lYG{5VXP6yeC&nMqQj|idQkKPfPkGujh5pPg+Bv1Jks6tLk5HB+azWmXaOZdrePE#N{n+oCn=YFY?YV(kFuw6'
        ')$WVkH}_+|_RfZq8Hp=m=7PH(@5;halb5Gw4r+HXa3oBt)7hp~47P|Aa{vZ`5`|t^WTWUgy(~**HT}E&KG~N9FbEi>m+ujb>i%(D'
        '`_WlO(ibS5P1Z+pv*Z99xes!u`YiVmP=hqOi*~S#@$(Jqac$P{xPf@}q4bmJQFj6wWVstlv%x;PdUkKxX!AgD82rTB&;&NQaTk>+'
        'zP@8hX!{`r-%0ukF6lby%Py+c8u({b2yKd9NKaWI^zmjWt-S#^J$_gAw6SO$8JZ>WF@GuDv$=(9#}95Q@FUQtE;6s796^NIUZj7R'
        'q`0{BpT$_@TxF%#+&icV5%<%!;<Z*POuK@>kz8Qqd5HxQU-`pE?E0MzK~ZZ0S3;XW5bo!&`n?LZHUpgZ!Ad@A9ePbhq%lgJ4_!Kp'
        'flUV_BQ!HV_bCxvPUPl~P{2jXcwP(`P4a7g%(~qgv=SUPQ7W2Z-7fEmq6@SiZl-qdrF;F>I$b$jyZ*Bxe<DL`EM$u8B(-R~f&v!1'
        'd@O~PM7q6cZmHuR^O{>CUDw9cLQg)cOD<{>W3Q@u>Qyi8RUhyY#v<1S)4zWuzm`(naz%YaW)D-&J(fr;u=lC;N2TLB;$S8?*XbzX'
        'v1|z->e*Ret@_QiU0532g(eqVVg-(`O;BT?)Od3t?#ki;?`k&7dlzbs1XZWr^qGVxkiQ6=nmC)xV6=mtdfQ|)tfToxgjsyfS5|Tu'
        'e8dvlmLOSG@6P^S_Wc?Y`D-)H6~{J<;}Cd|b#bOm{19%hh21i#*(%z-!fQur-VWG#`i>yQp|pK-$SISXS7SXn>@hjktP@x#?F{PD'
        'tx$BfxTR|>W6@NNK!V=DMbN7_DK2B1dVB9=!ecYr>jhY;yDUt3dMvD&-t^F$7g+X0QuH$Pio@T)=h68^Cgvq(g_00boLJ*(lMjU7'
        'wN4?cX6<ru=(v0@70C6+*lIDO9rf8c|A?PiziuUY-h=Ne<M`{FC8B4Y+btJb!3D}-^YxaL>UZ{_*nitQr@Xr7K%FwSSXLL4c>BR{'
        'YM}UVJd$IvTkgmcx{k1Cf;a8{14?9HYw&gLm%>3`O%QUOW0G|ga86|T4Vd}nhveIr)CirnTiY1itAH}rj8m*>s26-MT8fJ1uU5!V'
        '4@q}XuefXVd01`J4><sDO8N`iOX)&QO%|ZYMC&o^!EI`uY8)13a)89-;>7RZUkJTAG?ss>R(dlX;^jQcJp17NFX;vje=^5hv2{mJ'
        'D=R&C-1_5-?}E>tRIlFuo)XI%ba2%rsQY-}*M|Vl>6?II`<D|S8TeJ?Z3f|V5<)Q2mrfs2=#@enoN#5MQR`xoQ^SkT6({18xiYGB'
        'UZiQ=Ir~gY;@3qtWDjRP85j@?wpfPP)2epp8@mvadutcy!<*-5)Y(p6rj)vxs0lR#rQF=adGyJeh}(-Wh>v`Wn3kvUoxkJI)j*S*'
        'hH0W{)lCW9Eo}`g3ME;rmW6~sz)HWWkCW5vIWt0)U^oW4I%NoaJXDorUwH#Rle9DyArufrNrz5i3={CPLNr*Ni+pXeBrp3A#?vh='
        'mw1+zE8!WfiSmiw>E?a)$I^RtdJ-vTE_ds-XZ&1h)xIfrT5{$$e-2$#m(3*6pKy4y_CXx>@!>fERrp36%v_;wQ(J~X1Ooabbdb$^'
        '>Z_Lkb{%HEkN{Bt59ZGSoDrunkWC>Qvd0QoM3F9&27vnQN>g^r*{6^EMz^l&DRYn1r@I}Oqx}3#bgGkEdfpNYCivt9>scC>e;^6l'
        '7Y?Qo!g-W!*1{Hg4LZAj?4F-jP$?wQflO!(<Ttnc85cuixbwcRKW7<r$rasX5w$ps&zd&?SBDz}Uq6=xs)-OK$?XA2r_1G61RZe#'
        'h!=spK&no?^XHLMMkVC*gf^E>!_xmRt3=Cp(xpApY^@Z?YxTQHMt6H$5;45m(>JgB)&l&&+y+m;c3fE04d;B0=!}>213#%L*8{kq'
        'U2ztbCUY&}hKun<?@yeCZv{L&)3rTXo_)_tapwx~?`OF}DhH6Cuz9H&*8_yqm0NTmf9o>sQ`3V$+Nw3?IdIrB`hV>ORA*=h3mWX#'
        'q9AAqOte_6SkO|-W=kimO?$g>im57!xgQhZ6=}%B<lwQw-1<ZB!{(;W??hZNmfx?qpSojm-J`i>R9d6KF3HBoWJuV=`h|)v#uM|A'
        '<_Kd$Y~-xbEq((70m#b|4*uxA#vZHnd5qBgpP(-Xvl-y}`G_*wk)A-y2iHcDlvrN(T<b^cA%nA(*%wg`W|8I>yU3%eTjk|vgMI>R'
        'D=XKvGkGvRcE-{+3VNviSL{OUFj+r%EJ#e6lQ+Y`GQM^f@5BoTFSvc2l-j{w{CEbgeJ8DduJV5kX*Vb0Dy&>Ss08RaEYE-D+c4xn'
        'he+x_V>2PDQj%0CGfCgxlk)h`A-8WmR;fSV=J-gnP{6L)eWs!~lYYjCp#Kw3pmRC!{6tH3Ub828-96Un%i@C;bFLC1@nSF%GWVBo'
        '9pAc1gsss^a%JGCYOlszi~4@Ww_BNJ&})*r^r!G1UC$vm9_>iB=~*?*KG&K;W4P~5T5<PE!K5guZAhq3y0ES$>#=AY@PqqrSY}(e'
        'QWt`(>!Ns#Gmi*1jmzmHU@0}sGgDOCQ_%En^$vArM_22F(MZI(P9@3s6mR$1Eb}n=w$1sLX^PTu6~j<7BzX<kX_07*G@vUS&ZCF&'
        '6FuP$Jg|CA*m^ng10@XflN@e7g5Xm_0ttTs3{`kN*5+R>+E`_})O~FHWm}b*;Oc+)?WM&VTs=gOBTs|;EdZ4rGEhS3byK)x-qFB%'
        '6UJF>wwFZ74u-hy5Td5m?v44~BmfYROc*f)RG2J}#u{A7wNZOcXik>|w`U_8P{E9{Bl#GGx>>HX(3w<XAO-=kXr(^}3$Y4bVREcZ'
        '5O`TMXifb%#t<;6@DKEz^A_GUvuZyF!*q+(fl>i?$FyW$H2=<XH~u%GiPfD_!$#5X-di)Acudd@FZKHPlvY2nudvtfe69wj*7Qp4'
        'bk#o)A^=>(u1*>c;4FsXAIwdJm&awM)WVu_qH7$y(;Ms@>Y*2=ATXg3iy)G;`vJhX&13#CI>Wm81nwl`G6?;LHQo*7NmtI5bDSlA'
        '8+hd<y&gQ$SW$}{-Jg*qAUe@ZJa;hABv@1qnr)xHu8m?H)aMeeErv^wf>)9D4&|I;mPIq|8yk_VIq*qVzL!hc^lOqXH*%k&>M)wy'
        '-QpeLaGsw_e;B{;Ckyx^ueT~_59|Q!YAt5OR|+l`;NS;S-!JN1|1{f2v}_<Y8u7;3=`c|y4+G-XsKZ+&);XD2&hISQVEL}5qm~DU'
        '&h~N`lbo!b+|Vx5n#CQtf{+c_?_)iztj|hR_mf?m1qKcAauBvxY*@o&0VOztbz2JWoeip^mFsO!^b1&rjmi5gSyG%4EMm}XsS^7R'
        '+@W;)ACIT<pZ}Qj3}vIuHn-HuB2Ae0OLmGyV#>IhbqJo6<<|S-SOQz}zA8+?j7xJk@?nTjX`n+pG1*>Qm(acf*^1^(S`D7Pjsbls'
        'si*e;%y5!EU~1lpHGZTyBT6Rn3X#xk$)oUvHu)Al$KYMI!V<Q6;$%R9fknueZZye>C838gF=FDb-v3?k`MNb@OsUjG?|*owH$=?*'
        'p4yHsKz@l}@i`hT;Z}!l{@6RM;vdqI-qLs+0K%CSB?r9ieKO6U{&A^0fM4gm1hXw`{zO;dz^uD>j{E4#*hws5AKF*E_h{yEr-t3B'
        '``V)?`Ktd{RMBYwi^4(4$bj}^RydsXOWw71U@F$LcEPsUCXR))ss4#lls4ex8IAfR3<PB_HNAwGDzF$n=*dm2tO;fxTOj^Wk4qqV'
        '*q&AI<Zy;uN%$1Z8~N@p)?9f+Co$D<=+nYsLr>~J;!?n1ME;S&8ptL1mKR5iA8^S=?XwWOgK!9K6ITR}81*AC#cyoYP>t?1mTUbf'
        'JEdMgZ0eS>#ITBSN^<gT<<A}v08GZpAv6#Ax#OU_KqC8tc{;`~xFrsa7iG~jRs}Q1+p9OdLLPvV<|(>~ZOkZPYZT`K#0ISmr*8?$'
        's;gkdPsf>59`XJWy@!iZ+mIaj%dE8<892A5%`sQ*P5*q**pW<F2su(nGJw?7Zslip+tyn6;i>P=0|cIpB4p$Y$$~#{@`4!JTo_;l'
        'rgchb3QHl&TZ4uqF(R+q&syO<96f@H$xVe?_nR44?so%SH&x1Gl5-%uShpbj;KOMlBmv|>UuWFQz9nH#=il^->I#<}Dt2tXc78#?'
        '?n8=+>rU>v{`MK9-?a0Zgr;bDzZqG@y?h(w`N&jhpCcdWs}XqC*!(!wO^xjZEGnt&lpKt!${DuP?x2TQl+`s!<@o~RJ%2n6O9Q2T'
        'v>Qt!1f#^&Dr~p$Xe;>cGhwA=d<l8-wO-vmq)Z#4l2yTybqZoaFNh(V#I;^!p%3&x5{kVq!&+n%VFd!YW@h?Vt5WiD;zYnF-#7-('
        'P)DVW4YDgw*enZWTx(-kfF?Fm{GkNgrpw4_?XRHx2P#gm<k+l`<$Q~DEFtv+Vflv3?Mw%w7~pKQqbNO4ZKV6awRVY^e>bp%ZbHNs'
        '$w}$OAH5n}HV_#v0~Knj#vmv5wy<1`ZjU?~88R?!L3cPrq(2h@E8nK^!T9@XHnnOR{auY#;V}rqH~1qI4BeJlhO9?;ndSI^wc^s|'
        'jaD@Hu^pNJhn;C_vC1m0CS_#uUcq%eg#le6`Uuv+;1b~fYk&EN;qKEn`wN~w7F2aFU-N|wU-dU)h3~-k;%|+QFTMHO0eervl{uFS'
        'az0&#n=nDpLPLER0~2SFj}Z$UVIuvnum<Q*#%6^l#fDa(8BgdFIM1?nHcb{ck^|;RDfTUG`KH-zhdHn2t0V~4-Bl0mBFVE@^?s(s'
        'K6--@m%Ta<<NNyZ(FTNU$yjWbSK5^B;03&1!BKB(EgP)1af~jYqTh;gH*wLwBX;lAR9ZtFcJ5bF-Xe?HilqjZkX0iq+!U8MAzc@M'
        'mE)(H_2}7&#7m4mm6-u=Pd5bMUIIkp3RnS6ARszeOWI&Y6}X1{gpC$<OZpH4OvaZcj0a}zo@wY>D0BfvOY8gLT7`+~fl{npTmJ<`'
        'G^jH=QZvKj{fby(YQQbVZ1VNAkz{OtO~Bpx(KUsdADMw*CIH9)>ccl^!{K!*@x>qWfE0JW1zf{hIJ)q4o$i^!-#Gw>r~7%W>LXBN'
        'XYZo5>KD=+r}Q=@c#<D%XHvYIyeIyx<mz%JjqQE(O$<qjXzHW5Dx-uHt?Ocpb8-=-u>8LoCuR8ge|xYv>Bxd-LX^~%h_Nf7&aMJs'
        '!j6V71hf;=cf;ZvITv>bPOVwRIV^ln70jG3MMSZoe;bGe8#hJBDo3XP-a_;OVra~grK7rh%m$v!8isgVQp`(XfS-c4Qsw>l@=BGi'
        '000002A$Lfj~H|R00GUu0j|D<0RR91o(1@g6c;-%0{{R300dcD'
    )},
    'v2-budget-empty': {"sha256": '85602f28834cbea97fe0c3639afb2af0abb60d1980fb7e686bf0e94c8a12d063', "bytes": 2264, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0V_Q8C?K9h=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNJFz)|Rg;Ji1$@e|IuD|Rr$SKD2e6N&1H`;e4-;O%Zc_8s^9G;*biwVPuAu!x-u0RlFkE4Rc`DQg*)6dpRCD_U`'
        '5}v^Gsd@%DsEJQHD>=dUL8>#kHL0#Nx|bTGtda9t3ROj2Cy9z8_B$a%dV;W^gRU^>Is7dX49BKgV8}1X4!POf`q|IqErcqLyf8au'
        'F-0V@VfLVUwXBl5C#EX-^o8@(;GM1;lmrn1+!>2PKgJnG)YO<V3rE<9Y^tiG20U@aLf#Vt)Yy-|4_^OW14nId3hvLLuY<~8@pe=V'
        '3jiiyVX27*FMz3cVfXV4#aey?$1pVGl^Wp@8=xI;ZEhvjFqAK_;I977_DZW&P%EJ)s{3Ec_*Q4ca2w)xlO0AoD3?z-G$xej=2gpy'
        'D}RNO7L7O^Xw#t<5B1ikpRs7Q<Yck#UNP`dHlLBWKZx9%JlPg1KO;@CvimYSA`4C3Z~)Uh@MVyYBwXv_yM^54+Kr60+6V->xc;tz'
        'P)-)LBTjF-l2W8Es}cKtIa*pld5YRcU)lUAT{BZEwff%fj$G2#sqc_Ntbb9T-4@rgIq*S_{7*5{_Ix5EKw_PwZPRAeMdUp3$|E*n'
        'fV85N&HWx-VP5vu7y46fO{>0%@t3&%L!Fp&n+M8Jy3{`d4;%BK00000CdQFR@-_bQ00FfK*bx8#>qRC<vBYQl0ssI200dcD'
    )},
    'v2-budget-context': {"sha256": 'a404a8cfc155d991c4c5dadda1ad73700def06ef699d4a570bcaf3c0f21233a1', "bytes": 140799, "lzma85": (
        '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;wAnMU|j$`h=@ltMYFj~-9dsJ-66XofT01AySXk|!;Lp{J)ckB6Sbf`MeCT+<x}U~dbSNC'
        ')tF_`;znftF&Pf^Wmpu<F>BwqAF9dQjjLf!dh(2oHl>O*C4HJf9S9ij0I0v-Y;N67Ir%r-tz%Qam{OH6KWua5kDD;r6e%`&XVPg9'
        'mJzyQ&5=e(Yv@a^0h(z+Qt^_5b8;W_^6kcJG_v+()Tp{@Y|31<gUT_|639?9sTNhKXzAZmTXdZ7{urRKTmJE%peQ*b&XK^3TNHzC'
        '2F<zwyhSB^fxljp+#K7Uk;7nDYSw@=UbvmjO%==Dd>!jiVl3=Osk9G@j6GFgPem@(L5FliTT-W|p$U7D-oOM@(U!wAF6)ejf4mtu'
        '#tV!dxy@)*2tWy_j+{SnEU+6Dh7y3urO26WOxkpRl<#i6S@Rn4h!*5f2zuG<aJ`wn9dr-LoLOktIXsDZJzwt4LCWL@v&|d_M-2-U'
        '`f$leOsQ1fJ?0sFevwz-zV-@=2&kf?Tx}aZd#me#CkD&y@L&m8P7BJy1*!TwW*W^(yo#xT4f6}7wzZu9Edr<sP*chZe<RW4O!fl8'
        'V7A1Z1s{_bp2E9vPzs&F=#%+s+*4&Q7K5^gbH0_G)fRtw)|uu;d+&}nV%!bFuqS`_t>A6g+r0W~F6n)cUY#CwqEXkL(#G@)Up_S0'
        'ugs(C<1s12ylZNRQP!oe(Dk+3EIp!J;COflUtC7Dx^1uFRlL{pv)4_r6DqtXSk3Y8Sc{E_0}3HIa3ufZ2l(mZLKjZ4OhyC83;QFO'
        '_)6km`kh4|L%WBnzpw<w>HS7bG3tsK*=0IV9<s;jIg3?#$0JUe_K>JG3Nb0{X5jtF%Es;;oB(j45{5&I5rB-axBd+R@;~#|>$Kb~'
        'urI34LY)0te`dc@ZoHC6>xQ4XjCmnQjxH9hF5?8WhxUNZ?rJkM1@3ZbR3L#NXP;`QcNp_t+;=PUId4*Jc5sXZj(B#AIuM!j?hV2z'
        'u??(12N4Vc48Lo?8JP-`;5n!kelTyLC;&AlKh;|Zb^soobgd}pDpSs1{!RBL<(JezArt*V)a`M9lyOz!9v%0af<qSRNr%K$1G1i)'
        '!1$s-zj&fMytmP!sAUWUf2u?PrKnG@fN4M$+hy6N)@04Fyh!)Ab9q-{zW17KwD{LW5|NjQxJ6Y%My>CPvjQV%YZO5ZEJV5>Z!7{('
        'TlVGZzXws;+@_PrjSMcLv}RUrBs5S-Lwvz_i}S0m+R?r%{tjL2ap<rEsHBmeiXEZ?sp?&pAyWotlzXvelT-!5qYJrjrew9#cdJ4t'
        '{uO$PFU>g2Ei2c3kBq}D6<NiQueJbk%Q<RlW|?-AW=mk)A7>f~T*a}#D#Wh<0`>O$@!PgFS>iD)Crt)bw#)4^TPXbaB2Lid9kcrC'
        '>Y*Q2=wn8!tb!A^pkb@v_}|qiX;<94LUdg8Xt$fAS0*-yTRR)b<#%y`+4LDj|BU9Y9kGqX>h~A@E~IuP;f{q3*H?lBLpSqz!2@!5'
        '*RP&2SWymO7ilWipKTu=8g)tfu@%Z=_oFQ*VE?{Wm#!8=$Cb;^`#YtmYBFzM*vKT`6K%&P*R?yY(S9AqO}u<OK(zsjH}@L>>k)Rc'
        '^~S1wuhqd#{f#mwe{g3C`;W%KK`cfMorf`K&Q<|$#nK{pr`&cUj%Q2b9s@5n-HkP$4A=^m?$hVaRP8o4uNE3=YP`EPu#+Egq&*;I'
        'GQ-b_N3hZyMZE79BL>H|vb<KW+^)^N7!8|ZMOpxKwE@Zjc*O2Js~idKEf1m^x<M>wmu1n?zRGKE=Q(qR1}4arO$YW5!|fw^-bNkV'
        '1ijMn%b!N|3yknWZ&kZFSb-=88fJ-<Mhms_R7eO~CWh{e*V`~CW=Qk+y=t+vQiK*fSx3@FUUEP}Gl&6`xwHmcpH7t1F-B)>kYl)*'
        'Spiry5Zr^RfcpIclmubWT7{OJ15?q8*XYKrSEPK#ux>2zmMr?}s(UMj%>i2C!d%!%4r7HKhl#;Q<6^|-SU_@$E*sp9*j%GB_Kfg3'
        'vbVoAL;z^TyfVbwGn_^H+3dyphmLcFbMNws)QpIuG!k`#+7MPLE58!sBxvc^CL%+hdnZTpAQH1fck4#pSm!ma_{7md!r2urh;1Pm'
        '>&%bU&O8S6z4#o}wh2q*064F;q}!^k5tdz?2%dldZ+LTOqMY5SW2|*TRQ(Q^QdA5WE0FqXiy}dApy#X+SA>>ye$fLT1U>&HF%9Sh'
        'gRU$-?U`R)GuU?raa~PvrE_EBle-lZ!AnKb{|q_?X5QlCLR$ZAqRQ~fzOg?!{b<O2^PU*~ziMAQtxxm4u-x7CrlWq}C?XU+aXxzu'
        'b12VfI~~j66&rMrS2kvZ(RQ#MxkEtk;?bWennMcnt58uH1?>O>ZHttiZ`Sw%K%x5vUV+sAO)8?_!oeJ-TKEN{e&5+kdf)bXjy}j$'
        'Y<<^!65)e`;DGxmDeyZ*j3-Uy8npN~Vs>%itr+AL&p3WjnmLu==@*!<M;)S)mnXl7r@4Mv08K_v&zpU8uW1kIYF|j#NBJG0!tUOo'
        'Y2rd}pQ7E7|6}*)ou~(kf2@f3laT3Fd{`;KxmD_rKCB2t(gZ^!_lYL@{$R@O)5>B?-Q?U7($l3DYi~u6dRy1;!ja^7w=9$lUkj%3'
        'gyTCVS}iI#(#<X-rv>+0j74S>gYhK{&JuVO$09CK;HW%N>(}zw#@xBaEn?oW<I`r*@bdGxvzN3^rW%?J3P@=G;cjiYa-ttv^Md6>'
        '23i}OQH^0ALZz6j!ZCg=*n4j5eX(Hev0pR2!+OTq#%T3h!eg5U8B!s(kG}?^ZPlqVz}xn-T#gt+-j@h+Q*8KlFiOPBLN4#pv~=|K'
        'oG4lV*c{kMXzj87%126xVf-9M@X6YVvSR$?t>uVc8xBMlLjb6&Lmv<&!h$v-`9d;<ra#JMN5FLbH5_MjST40!9tJV+b4dT?Ib{^>'
        '8yP`)f7$9x^!amvgBHk~(tvmixj%0xxlYg_dx=03f=@jA;f8HgF)I?gW6{o<4)ejqb+)Q6{!;^Q8*DZ>bW}EJqeTa^)9Rba3Pvg1'
        'u&9LD$uk@79OkQpLgHJKw`}*?u>4X8cl*g#k>G$M{@NLQTZ_Yp6>~SbJlu>Hh|&u|lLyxXa%9V-%h+^*wBkHj72Z@=t<RS$RLR39'
        '()I0;U6+yGwtWwsMXKIN^A%+`b5VEX)O^HSaMboJ2im1~RgBpuh(kb2i5a+oD1nZaJ}j95W7U$E+h8Cqu&=2~OB`EB@o7n0<*gC!'
        '??dc)CwChGy1w4SxGMdp0OhG1!X#tKLFOu8!n@fW({1YV!%etVdfXJ0&268sOub6BB3|l*xuzf;D|?2yocTp@ZNn#$UP0&2Gv~1b'
        'uWL^4!mWbYG)TQzB2<<3YRq;GLNmj?nM=51k)byfM_Hb#Ca$CHb>e<^o)mAN5hSun*_O;L58(+)q?Vy7w0^V;nIf(?SWPKDy+Z}X'
        '%>Vs&E^C}}olXCiGIuFyd73npiU(ZDdLy9X$;yzh^)#3_(q=Gi-&Oz>|F|Et8~f8Z><x>?&*B1q^dMh+OdI&U+ItQ_8|jQG>O`$T'
        'NdtETw8=Jkd(^!wX4SbzCGZ2!gCcw*DzX8%wP@T=LhUaUG;IYQ`cQY^wI-U4Sq)TTo3K@SjEq}h!I;pAA2En8FtN@M4n+6NDMaY|'
        '<OtMAXfJ2CYe9vyo`rr80{6ev305BM3~NuY4l&pU`zxeim<X!!IWfTljzZ&ChTS}C{j_C0ODcCt`A(gn9=9FU<jzk(+Jwib4=<P<'
        'l7mYxVXO;v!9*WGSwzGEypVaqE6&$D@uB=V+=%T^ir93M5zc@JPXERD0RkNxT@mU{0!=!Q>(<wBq`bT~%K3(%D2Xx6JTLdt2KH5F'
        'wOj|g0NZq&^6iIA*GF)oY>bt4HOYnk*8;~P4|8H|+8&P(0toq^a{(C?TSEC8NmD?b9m9JkRZ5t>ijh|EwwOl`*X$=S@Hn%sil!@p'
        'Q^`Jp3+o{GTxr&czPRr`O{>+f-2ACsDOMht3sj<;H9txIWBm+xtC9Uxs#0StwY8Cr-Kr`+(Y&}SpfEvYOfyp_&ku@9h#^U(bH`}r'
        'z+myE4#Tw|KiIWX4WkRe6E<1#kIx$?>Hv-k+d&3&drd&!5PPkp2x#+~UjN`Mq!W9o**J@$Pn1>y(3*ytAVx@9$FlDuDslwjelm{N'
        '{SjtGDwk9?gBM_CKs_I2-}%kt^hN>Gk-P7{{;c^Cs<Dmw32wl-<gMXkn+duxa{P|Mdo9ODHwJH6p6CQ>tV9cnOON~;Y`qgxesodO'
        'c-3iFGcDEv=`ppbp%d6S=dGc^x%UbJ^=jF5+98IU`-K6vha3yeWT=BXUQXy%LnhU67h!Rb!G#$^(6t7VI<|LGknewe#s}G<s*r!I'
        'MiaDJifr%Tv=;5}Or`e|jp1!~5)1p1K=Vu{Hoo8^U?PK8(2{hznQ$}Ja7@&=$QDFE^wQ}xO=G$@D|DpWihSXcUvXHv%<~>v?ZetA'
        '#<Vkon#nMX*X&{9NE-W(99Qyb{aWRsU8g~Vwz&ZY+~pAz-HwW|y30i!#u-T~J(e3gY;@a^h7s*8?O@ufsoE5DXH5Y~DJ;YLXcN0n'
        'S@?%qnlkBZ<YojZBtz=K?;y0Ae~nPK(OK`{p6YsW1|%^Px2LBFkL%8)e$e7~)09y<2Sh0UR`Y#EAY@>2aRYOZQ^tn$6qINPwO?1s'
        'CpZGoPL`S@Gv2pgGWe$LLDWgvbv~F?!v5WZN@bsRu`w>ZAdJXcX7BY7viW$#kYFNqhTT;DZWpt}ZbH_&7lx^vD`8j12(xnr7ORFY'
        'fFUy7QXdAl(#if*?DwcOB%uD7|GMt~D++?C&t!hCCt9ZSNQ$rCn*3P~Irj_(jd?DiqE_)7Q4r7f{H&5WF+_X!pnN}d16bOMO|(|$'
        '?8SMQ|4Xf(NNjc1OQCInFOdW)&Ziq7@=*uXf5q=jbr|WAMKM=zG3#C-FVQ}#GXtxo;(#kBbVNh7l^{kWiW&te&v>l#BUGbw+q)S4'
        'H>UPPBDVNfL^M<Mh`EaSa6qkeUtS!Vjz!v{qLUo|_}_<_(`p3Sm`+&@9(St%_;Mwq7#lH<00I0S|H}vf1kv;LvBYQl0ssI200dcD'
    )},
}


def budget_rows(name="v2-cap-hot-zero"):
    fixture=BUDGET_FIXTURES[name]
    raw=lzma.decompress(base64.b85decode(fixture["lzma85"]),memlimit=128*1024*1024)
    assert len(raw)==fixture["bytes"] and hashlib.sha256(raw).hexdigest()==fixture["sha256"]
    return [json.loads(line) for line in raw.splitlines()]


class BudgetOptionTests(unittest.TestCase):
    def options(self, extra=()):
        return reader.options_from_args([
            "--mode", "budget-final-parent-v2", "--max-final-attempts", "4096",
            "--rounds", "4", "--attempts-per-parent", "2", "--cpu-budget-ns", "1000000000", *extra])

    def test_final_parent_cap_preserves_prefix(self):
        options=self.options()
        self.assertEqual([reader.attempt_limit(options,i) for i in range(4)],[2,2,2,4096])
        self.assertEqual(options["mode"],reader.BUDGET_MODE)

    def test_original_options_and_bounds_retained(self):
        options=reader.options_from_args([])
        self.assertNotIn("mode",options)
        self.assertNotIn("max_final_attempts",options)
        self.assertEqual(reader.attempt_limit(options,3),4)
        for argv in (["--max-final-attempts","2"],["--mode","budget-final-parent-v2"],
                     ["--mode","budget-final-parent-v2","--max-final-attempts","1"],
                     ["--arm","structure-specialized"]):
            with self.subTest(argv=argv),self.assertRaises(ValueError):
                reader.options_from_args(argv)

    def test_v2_invalid_bound_and_bool_rejected(self):
        original=self.options()
        for key,value in (("rounds",1),("max_final_attempts",0),("max_final_attempts",4097),
                          ("max_final_attempts",True),("cpu_budget_ns",None),("mode","unknown")):
            item=dict(original);item[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                reader.validate_options(item)

    def test_structure_arm_map_is_task_bound(self):
        options=self.options(["--arm","structure-specialized"])
        self.assertEqual([reader.actual_arm(options,i) for i in range(2)],
                         ["maintenance-limb","blocked-zero"])
        self.assertEqual([reader.actual_arm(self.options(),i) for i in range(2)],
                         ["integer-paired-general"]*2)

    def test_schema_cannot_promote_original_v1_execution(self):
        values=[json.loads(line) for line in decoded("budget-zero").splitlines()]
        values[0]["options"]=self.options()
        with self.assertRaisesRegex(ValueError,"SCHEMA_OPTIONS_BINDING"):
            reader.Reader(values,None)

    def test_mixed_raw_schema_rejected(self):
        values=[json.loads(line) for line in decoded("budget-zero").splitlines()]
        values[1]["schema"]=reader.BUDGET_SCHEMA
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"mixed.jsonl"
            path.write_bytes(b"".join(json.dumps(row).encode()+b"\n" for row in values))
            with self.assertRaisesRegex(ValueError,"MIXED_RAW_SCHEMA"):
                reader.read_parent(path)


class NativeBudgetReaderTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/"v2.jsonl"

    def write(self,values):
        for index,row in enumerate(values):row["sequence"]=index
        self.path.write_bytes(b"".join(json.dumps(row,sort_keys=True,separators=(",",":")).encode()+b"\n" for row in values))
        return self.path

    def reject(self,mutate,label):
        values=budget_rows();mutate(values)
        with self.assertRaisesRegex(ValueError,label):
            reader.read_parent(self.write(values))

    def test_real_native_cap_is_censored_with_all_proofs_replayed(self):
        actual=reader.work_oracle.verify
        with mock.patch.object(reader.work_oracle,"verify",wraps=actual) as calls:
            result=reader.read_parent(self.write(budget_rows()))
        self.assertEqual(calls.call_count,20)
        self.assertEqual(result["schema"],"pon-w1-parent-reuse-readback-v2")
        self.assertEqual(result["status"],"safety-cap-censored")
        experiment=result["budget_experiment"]
        self.assertEqual(experiment["prefix_research_attempts"],1)
        self.assertEqual(experiment["final_parent_research_attempts"],2)
        self.assertTrue(experiment["termination_budget_poll"]["permitted"])
        self.assertTrue(experiment["safety_cap_reached"])
        self.assertFalse(experiment["stopped_on_budget"])
        self.assertEqual(result["final_stats"]["tip"],experiment["final_parent"])
        self.assertFalse(result["controls_completed"])
        self.assertEqual(result["counts"]["research_unique_admitted_within_budget"],1)

    def test_real_zero_and_context_budget_stops_have_no_credit(self):
        for name in ("v2-budget-empty","v2-budget-context"):
            result=reader.read_parent(self.write(budget_rows(name)))
            self.assertTrue(result["budget_experiment"]["stopped_on_budget"])
            self.assertFalse(result["budget_experiment"]["termination_budget_poll"]["permitted"])
            self.assertFalse(result["budget_experiment"]["reached_final_parent"])
            self.assertEqual(result["counts"]["all_work_unique_admitted_within_budget"],0)
            self.assertEqual(result["retained_proof_records_replayed"],0)

    def test_cap_cannot_be_promoted_to_complete_lifecycle(self):
        self.reject(lambda rows:find(rows,"strategy-end").__setitem__("status","planned-rounds-complete"),"STRATEGY_STATUS")

    def test_cap_cannot_be_promoted_to_budget_exhaustion(self):
        self.reject(lambda rows:find(rows,"strategy-end").__setitem__("status","process-cpu-budget-stopped"),"FALSE_BUDGET_STOP")

    def test_wrong_registered_cap_rejected(self):
        self.reject(lambda rows:rows[0]["options"].__setitem__("max_final_attempts",3),"FALSE_SAFETY_CAP_STOP")

    def test_termination_poll_is_mandatory_and_predicate_bound(self):
        self.reject(lambda rows:find(rows,"strategy-end").pop("termination_budget_poll"),"STRATEGY_FIELDS")
        self.reject(lambda rows:find(rows,"strategy-end")["termination_budget_poll"].__setitem__("permitted",False),"TERMINATION_POLL_PREDICATE")

    def test_specialized_arm_cannot_change_between_tasks(self):
        self.reject(lambda rows:find(rows,"charge",lambda r:r["stage"]=="arithmetic-prepare")["detail"].__setitem__("arm","blocked-zero"),"PREPARE_OPTIONS")
        self.reject(lambda rows:find(rows,"attempt").__setitem__("arm","maintenance-limb"),"ATTEMPT_SELECTION")

    def test_final_parent_miss_cannot_be_dropped(self):
        def mutate(values):
            values.remove(find(values,"attempt",lambda r:r["round"]==1 and not r["proof"]["target_hit"]))
        self.reject(mutate,"SELECTION_ORDER|FALSE_SAFETY_CAP_STOP|ADMISSION_SOURCE")


if __name__ == "__main__":
    unittest.main()
