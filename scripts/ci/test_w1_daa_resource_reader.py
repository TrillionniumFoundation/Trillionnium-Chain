#!/usr/bin/env python3
"""Actual native 36-block rule vector and permanent proof/accounting negatives.
Unfrozen functionality fixture, not a physical cost or production safety sample.
"""
import base64,hashlib,json,lzma
from pathlib import Path
import sys,tempfile,unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import read_w1_daa_resource_research as reader
NATIVE_ORIGIN = {'scope': 'unfrozen native legality functionality, not a performance sample', 'binary_sha256': '1c3ce5eb936bebbfb72e712fd6a5235c1a75ad65f143ce50ee8b20548120bbc8', 'source_sha256': '37e83dae32256c367b5bb2345f45a336bf852ca2eb5323eb4590010e1c50ba3f'}
RAW_SHA256 = '04ecdf2789efa9a36488494af18f55e0c475f8e58ceb56c7524dd73f4cae17b3'
PACK_SHA256 = 'f564511835b3fba592e861c210bea341e406ee040d050e52856278919a94b566'
PACK = (
    '{Wp48S^xk9=GL@E0stWa761SMbT8$j|Nr+L@?8Kuh=^x21@*8tw)4X*JU~NyC{xtLJx}7q*>I{$bi8d5ExBTMc(Wo6rKFb27iQGO'
    'fRZyV{YGS4!`F1}z-}8b&crta>cX3rCxE<m7DWSIpt$&IC0HEX^v;>S#QXI>6YaVy+Fx`2QB-MYW#LS8`UkYR%vmho;3j-'
    '0l@KiZG{Ipy1_@><{V#KvjJK2A)V6{doOc1^dE3XUy>vFNua7sO)rE0H%!lfxU;mn3*UXLKzeJi<GQH2zyI>d+W>~*9Y~L-'
    'c)9ex;`d5T*SW}*(VXVBGvIS){QR`WxhyW<cfz8Jc!pZ&2|5@)4g3F`kxx+yuPcgKLzzpL8dt^hB#bRLf{PaX{!ar`YW3*DAD_yy'
    'gd@F^=$YJqO(o_}5W)-_eCve@ppFEJ&sRw^R_Q}iStqP^zAyMaMob>dYOjYlRGzt&x*#nfIdNCBN20CXE(-@b-'
    '{veCo0x#ZB0s!fw+Qohoh7JQkbFubBPh)}uPQEc_A^+a3D_x}+SQdR#ryv`tPhe@I{<l7~o8x<he1?u8vI0vecMy4-'
    'D}BPgzs1<H9<9Gz>wZLr)rP|{^Cj>kv0_BZhDZFGlsbXyCqK-'
    '>Tfyx=m$nK5j`woy{DcW1zGnaVeZM?A4=yD)>N|2Bpfw=>Dl{iIKU`Hz0v1zyhfZ$zSwDdGwD<S#a|<-87QL%RErwn{LE-'
    'A(jGs6;2aaIwod<XVd^U>J1{>;Qhwo|kIbG-CuHg$&ba)CqUE)Dmj0bj_^vPm90DVX`k@t!E4b>7*u_ACqAEj~R6gMK{L%I<9S(A'
    'H~9&q0GUFaL3>nIj}numU`i``*H`W{dvg>ZT;!eJ?J$w&Gj`^LQX#ZC@w-+Jg5-'
    '+<n*w$%M0M*d(vlGYiMNl;IWS)8_mZuJr>M2_LI_rF0ulT<PU_P}QEBgaP>FNtZRO-'
    '0*^vPH;O5M(+O3z#5W)N|q7Co6@<W1yTu1QhmNW^8zEF=??~;Oy&wBuLQ8yAJGcz9~;=5qrd%midsFOxu|HV6zum>y)cF!06&G9V'
    'mBJw(_XC#J=$C(s;+PiGGSG;FF=M76)E3#^o{}5B~S1tFEw+{8<v6Mg5x0=Mn};UG*`v+92esB9!-'
    's8H8N<An@<ERMs*`3d7X^PY=ip+dR~~JTX^9!1-m6LtCA)_poU!-'
    'Az^)z%<Zb#ub+Y@*0}+HiOH<P?+GnH_syugGfW#lgIftN;KbT@aH^22#i@wVQ|Yhn{7J;a|X!OT8dtC7R6zYk+Z?5s`C4Po25^g4'
    'T`@%aX&aETd4(qPdwFVRp}Rjn$XRvACm}F_Yt?XuO16{?Ez2DJz2ays3iQ$)DxDC4S65oD2$rO?=N*=ChtBD(Mj=DBF#<9Kv|Ofi'
    'KO<|`GEh6smP2>$p?W<@~_QH9{H=N?=>z5S#6MC4+$cb3ivGNe+1jjx<si9QAjc$W3E)uPyxLiL2VVA&`!ydr0|?tDTbZIvA2c<R'
    'pCfCuV_Jalk<D+<cc-Al^!YthiQ~OxNV^c!}`;7_6z2C7Gnw#EwIRQll>3E2#o@M_k2Qnm5nlM`ICprHi$=8xxA1SA8)6iS&t_Eg'
    'xf-{KwjIpV!;E&B$UX6y8w3cqy3;Q#z&m55ecR9)a-'
    'nt;9~Zmb)MYQQX%3AY6&m5t%CT3z1KrU;qjJ}E(O^i@l=5DPq6Z~x|aOrTg}9>>)B+D=^=aV>AV~|n5-'
    '}hf9Z5fg$ZmU<psb4{XUPckS@@0S%ik7V}V-'
    '$+;St&pK=iA4H9}eQu<08fLx^goWa;Lj>j2oB%Ws;&GV{)v^dw$ODZwnSUF6ByT8t&RB^j#U)|ON%e0xMKeW>jS3?`yu~Nv$ker-'
    '%MJxJQOiaRv;iYnF-&@<cGP81OsCxP<3uYZ(yABx`_wUy=$@UnIx%M_q-j~ALQ+wV7Ld1UR-'
    '0gjGDrt>+D+{*JRRXD%oTmJ(nUaH)Y*Wz$Jh1`Dzmnkt+#G0zZ!$JM+Xx~B9a`M26>?r9bbI~DTzmGUg4@`aW&6K5qFWBGKDj)K!'
    'GaWW#e`prP~hY<#~=-'
    'W`$fUuvtMNO;ca};@<IzJMeM;QOyD7|CLkFx_4IJOnS@4{#x`50EaXE#Ds$>{jnQVI&wL_`P;t!DYQpeSfnTo?4!RVDTNCs6dd<7'
    'vWfP^HjMsVqIbRUK+e)DU+dmsiD7T_Lo|cY6r(04gJ<0h;Stl4Pmw8%Zk8g_06PAdCA;l<f2)*}o#EHmPCKZhp`H-'
    'by(B)v~+4LqKVL!WR_#Hr&sw3iv1Hz<KtUS|O$5^l1^<X}nHL@sHw1vo8i;~+Ij_bu4^d#I^yj&k1UnMhSQc_WX&+jp?Qc)|)pR^'
    'h}x=B_vYRHd*+)*i54Q`aH6tlzk1FSfLq0#;J3?sV!hX{WF#W$^{m}ecgNQ`HPe%z6W71z=so_ila1~OgNJ?1nTQQfD?MSidel+0'
    'fp`4Hidstc*4l#`Fkh6N%jYN%WZx+s&JV^0%Y%KJrNAcIas=dESi*IuqKQu#O&KgwWkkOFIOA$~~qeGga{#}j05T2!>Ieqi0*b6O'
    '2b1a2?ugn{q?etDaEUT|Jjb1W2aD0hy|6gzp%@(}_~{#UiT?AN-'
    'k6Wm!ZSb|Gu^NI?xa;zwRESE2qynQ6+C_()XUbUYQ=7gQaz_PMvc+Zdukz=ykZ_sVWj8v|>@e1zX=r!PH7OW$$i2-'
    'b0Ez%Q1w*=}^B}mx9061QOBDkEFfJ~VX!H`mdGOKYWDz_}%k{dn11y!iDtQh130)($8E=~c(H$P^TDtl&rpnhjH)0w>g?T>Q64_O'
    '^gvc`1Il}!CH&D6h&Wk`CIp+4}c%RwM(;lx-_AX(o&OJ@u>3gaL`(%_CAa8*?bDX}=i{Ia^EV1FG={a3)A@1Dxi_GITJmUx=5iN5'
    'DVZAq<Uf;(?Au<wFij#}TLN>0lf4f+y3IaljZlOotbXES8V`1T|UWF7|r*j&6cD9kc1+i^BYE=G_kXE#*z<$&uj+lU5~@6Zj3+4T'
    '6(xo9ExJi~gq3_9-V6TkrLG5l}s8kxB-z~m#M51iYETZxIAQbZU5B()`9nN6s)KX3@XQV7EqrX-UHjx5~Y8uawIS3TRxhF!f^V5j'
    'sX1XSpl?yrCU$9*k6A@FxDsjKz@$-'
    '`GVb@#Qq1ljaR9OP3|UCO0s2nxJgDW+o;tj@DP^?JPjHf9wJKtJ)a`b5eCLmsA%wjepoPhOONk*SLXffl%qPhdwu<xpwv7D4yXE{'
    'x(=)JYss<go5oF5X^2UfNX90Q_}0=a2L4YRm-'
    '8&5@P(sj0a(4+LSStBEk22u3Z@7k|fYd9;)_hpZ)EQo8Rkl8pUTHl@OZ7UN7K`+Lr}{<`o^z(MRzG$TjTh&77E0r=A$O)Pwi)*{C'
    ';go@&>CoGw;Ja2Hq(Bb?AW8rF=g$AiFH=1zYC2ONDvTk63t5Lt^wBzx2pSD7;po<=xfZP?@bTt|m2mXZRBUr#wmW|Gv>rJYq?TL%'
    'KTB@S1ey3_JLZHQ*Z_z!(HiIXlFc9RQ_mvu1uNA$~6nW>-77<svPc9RGf@r-'
    '>hM4!J8~4XWMH;A+;EtX3hO7yyknA*Dv3%KheZ5W3h*uWk-'
    '0tTB&tFEty%t~buiPV}Sn~kbDxUUIEe9S`XCO)V@gI@<3i+G);eWz6Ww{h9p4^jr@sXDy_K|hW(TY)DQ6?%y5bvR=E?xd11v|#(I'
    'Qq92GS4Srh9m%Xyv#+X(eB#wQ;lGg<>TvhsNk2T2qHvWnxZLnMoZNEJ^9pG-'
    '7vZRnv{T+FlK;($Ik{F;loH<SqAVIVxI@WPPc+V?JO1KgxpT_VTDRZGhITc-jo}ZaCIBZ4rWV<DST~wVqXKEwCvi_GO(=%1R(mjL'
    '~{X!>CWqH#&!$l)7W#+;xeit=Qr0CNPWvDb(b0w!1~yAEtwFtcHj-5uGX(b#w!(jD)^MSj_dD&Im4J{`07k(pa>d6UnO-AK9Em>#'
    'wu|z9Bw&6^A3Wfm$B0xp}vXj+x!kj1%Tw>AJx%-'
    '*DtNJbM_fLDK<p0z=(w6lPt)%_XiI`F<P`$UD(a_Uyb2mt1L#`mT{0mC|oWFM;vOs5z5k+eg)k{U_2{1M89G8^q7nV^-'
    '7Z04zx+xQD@iN&weHTdeUn=kV@Y-8RloW@~%-~3L$`=QpF-)^dSYJ1+`HqBv7MfzUB@kcJiEt<8_`n@TVf{BO_h9g8Lx0-'
    'V!u<V<9m=5ir1l{bG?Bbjn@UAna7z7l<4TR6zj|G-'
    'R@In9Gi20~=BQ>ba;!CFgNTV6F1)drXoP!p3=1BkiJY{r6#|QP~~AlAn5@r@D@j<15olahf6g{w*eVZ7db@Aa!chGxIS$r01qxl{'
    'BY&#Pp}_%$-'
    'P?BnYfX?nY29hFY}+oQJbWy6L^!`LK~FkNLkMIo2gVZIe9gt%_S`_+Zg1g5{Ri=*Y3vVS91%;tckqg>kS1z2i|<@4$zo%Y^{hD+?'
    'S#=Y_kHiA)aUna%afZ%_^%PL&lMPS6?i2>7J=(|MucSb|p2OT4I5M@dNn`QLzrD{|5X%1%s2Os`UnFh%0LdHR5iU_K678$udnvx-'
    'to8JX9$?B~lfO7ry$ut)2HprO0M2@(0Qr81_q9k~i6i9LPMv#~#eMG$!(2F6uY#5O3JfZ##<5p6#Z@r9CJ($^#I`?V)_=d=GmErC'
    ')PPFujWyZOmfg28Oz9r{k3zW)h3(Vx4}{yH4MB>}Z+C6A0~I@Fg~acjQDFD(^o@;wE*Us!RY1f?kF8bH7nj-'
    '4kS#_@~{a1h9CmIx59O~Jqs;!c-tgnef)%|_JHFq<CJIg;ZXb~)+Tn3jzv9i!|pBdZ-(WTw{;T+x-'
    'u0s+bWYKM7lTxBT8=R}2~yKamOgEvM5<=r@&*!ry=Ey9t`ukR9dOpoSa1_c1tfi+KEYy}Og_O|Uh<T2CDbIHaPh=O{10)Hi$t<I`'
    'cvWfrl;6?oV-T}yEkH-mzSvUeFDIBSLd*EPqHfUd16`8WyQbK=7v~Gyj1fdKkQXp>+y`|pL>_I6sU}M7B6LyeKn@VSty=(X63g0&'
    'B5x@~pU7(cSNoVfJDhKuMm;G{R-'
    '{QRSNg4jq;b)W&v2Aw&sOtZiOe}UKeJZnreE*i52Ez!pe^4PzR6}LQ0!?nDbW@{geSL+i1E7jGZUJ)i?DeKa4&}Sx=S1avD#2?sb'
    '~MgoflxrPC}(jU(8*TJ{eRoP-hE(?ZKzZA<HfY|Q+jcUTJB%knO8ecB83s*1yXtZ!Cn{~%{<NGofsi1%xl-'
    '=a^g_%D6iqg{LixcVk+1G1Vf~6;dr8(jz)sf+9Rb^7cT(I@>4o`eSAGL%)=;SSHC8)j(*Hkv(n#ev^g)jc^^=X>u1fEHC4u`(s1H'
    'Ihr#RFz;HR<lYK1|mZ&jL^@@o6e`$r2lj!_wp=r!or+!zvol|s3o#}gJ6(XsIEBIt5mFz@$z>fy6mwjy3`mR4%DiX^LH6W}2ZVa+'
    ';@f+U%V8#h0_m+MiP+QjeRyN!(>Zrm|YY)V0A(Q(3CJSB-'
    'T>=cM&p%_fnVG#Ncwj!vb(m7JR&=B&v4**%jxG;YF0ft>HXb*SJ0nusFDGH__JUZt*34>0pO&IeEy4Y)Ulu55<N<DMc0N0~qi__4'
    'JQf^@9anLAx(QQOj|U4_-'
    '`^=q6bh(xgZC$+K;&oA%TOvykozrzCs2)C?#n(=jphas{&ugtJps0;dzF@BtfG8C{0GVj7`t*75Jvh!r%YXeCx?hR`Jnx|8$`S7)'
    'dB4dW(<i??ALVU8gc&%f~9NdX~{1%;239~?G}%mt+3{OKM$rXhhi!)h`R0R$WrPv%vIT2EIZ;RErc)z#5J4cz$%9myG7Tw{O0LwY'
    'M*^(oqZQ-w62Zh%JK5J)37w(B{eOQ8t-*SsW6HhqG-'
    'eiNU#VNgIxdxOsR&Nw?oej+y6D6Lu5wBFlkvN!)-{KCnL8Kp>li;IcvXIvJA8gIOjr-Fg}w3CA`r_Vj&}m#S31cvCO$8>N@VH>#X'
    'IU+e;btpWG2Zhf=uWE}Lryp^&Iaf~Q@jCflk;&%)$h%@^W6P_7bjG!o<)ZM?o4+oqi{D&Jc3*)9&Ay-'
    '7(yX3g~8<`j|TD&sx8fa4l;X`=ibo^?PoGI=(+n7%hv$6#}`DpeE9g}q{7W|}!wKTXbndrAIfl54CVa9+vU0Q8|`Pw?|H5qk9~TO'
    'og3Jshh|WtmDVbBCrJWY$l!a_NNnKq`Eb4s98HKw4EmJIqDk0BZznOf)8Yea|lM!1L^|E9>Cw9V8g2_(V7xiFJvZSp($byZlU)iC'
    'rF#B_I+PS+#7HLU-I3cC^dSAeqE)_mk9M)n3X76o_tn>KyY9b?No!1eZ>#LBBckysQVXbG-'
    '`RBiogy`wsk$FN)PhNT|j?!WH^|?FXZFRKWI($J&d7mcI4EPyq$6|1(UC?1@t&=5b9vWxKwVQwR|ZhOf56!ES@R*LPyz(q3h3ka}'
    'G2TAFGbq^r*7$XR4fs`8*$L%M;Vs|{mp9Jpsv`-'
    'f!fqv&z1Ueur4D;fz{sz{s^J+n$^D>=X?R=sL)x2qPbP0MCW&j+MjB=Bn|DiVwT|Btr#yv|yE^(S-sNoKc&7mpDf4CC@pr-'
    '6)~@E6PVp3oDkg7*QoxAW}x<)NuVLF=PbRlD-'
    ')b$U+<k`mgv)R}NcpWY=28WcsDk4B9SKOj}Kl3LGzslHHZH+aQ8mWCiVyX)8mg*}=UJ0i+&B^2s^f_^4I{*~Y&6j8k1yCu_j5hIx'
    '0XiIt&7=QtT_Qp9b<&j&!vb8B1MPt!m%?te>V;D#Se++vy1|=Pws_PxBqO1@-'
    'g;V5{l)+_re{MF1bEKM@>MVIIFy~WWk(0o*O>nx%Mgpo@Q4Gp3m_qz1TLM%}kCg>WLD?v6A#*UfhgN_~PWjbSL?mQ{&9Kllc?N&U'
    '29Rcv)v2$rcc6<ZOKmxLP4f89MVj}C@8tAHcM3=g)V5#&CDF1rqXqXp3bgP_qVy@znT;2dOcfh2|92O<NMZ))32U2}M6UmcRNniO'
    '({Ak)2&Z87Y7khCr9yl8Rl!q_v9&pAC6c8;6RjRBY&$G<Yi;>gto8@hPOLK`7R`;Prplb?2+<Aa#h?&mjDALSRt?rVgQ&Df6xFZB'
    'R_p~sH^8+=oR2VG)gv&rOVi~|Kf@n7zYjPKU+@@^Tq~i9gnAG{h^wGggPa{?1F;2-'
    '&9FZk{tG@xt`2P}CeV^^>hb#kNc+_NlFg47cFjY80BVR<N*Z9Eyjxs5q`itmJ=9xzTO9kF#6*wSG|f@f_H{!lnTAruZo5Y+%nRx-'
    ';w}?j`1!#_H-'
    '4uRX^VG%UmC%|(YW7g9@M5R2;Hy2P`%UxvR$s0+d4}H8Mq0R+rOdUad!@XkKVx#eI#4&{(%I)b1Jw6g_#;HfkwzNij49-'
    'NLxj%hHd=X8RYh}JF8S6+&kXA2w<_XPMY}iO1}Ysrs+Wbz2^!u$ZRbdPqvwgsc`P(-'
    'oZV!nrZs5jxcI8<jT}OI_)}cG<x0ih=PZ1*Gz@WOdV4lQDI$8CGj3O2>5hS)lK4}V);Y=^&n#@xj{lhNssW#6F98SZA}~O%k~=B!'
    '+w7iwd$hqC&8U*QH^23l50?WE$H&VXlj;XUO?_jjmUg~u^r!sz@NIBpIE(ZuL2C8GvyBi0IZ=Eo#+PF(U)-'
    'kyn;Tk2et26K9{yoS;ME%vV$7%A8pd;h~3wQo}+i&+v>zHV|#xp4V~w+@hilP_3QQ<H!FaV7%qUrhOd<cB8p7!V-'
    'I;Ih*aJpc{UHy9aLs*mJ2D^bGY4JF^Po@(RUmw-'
    'O8s|!7)S44ZJavn*woBxAHw!=P;;+e%H*Udpg+48FQe9|Fs34f$k{Wr4cBhDBr^^(h${H|B)*T-'
    '3nEkcg}IaS;{^9gtAc>A0agNE2`JgYa=FoUO#S}9n4p^nfx+of`SZnK<$^EPwt~~`iHXka$X7m{<UC2OBD1p-'
    'a3B2`X!Ab>GXimQCusZ;G=L$+(ZO-qtPVutSp~41TTQGvf3PJS*ZSbu{u9De|1!~;CxbfWo-'
    '2xf{|XfruOi;c)L?i1B23PC^@Ty&cM?+sc1QnzfaK~%$`jfeOPvwgi7(ZX|g6J+-xa=_XT%&aAb=wYi`1eq&-83jgPPYas(Om--c'
    'oKLSy^bgPioKmx2ucWMJSr<{%<CB5NhFx6+#mYDZ2=0W(e*qKEw2E+Z9~S|&t>(w${<_r(h~CP6<Y@X}^G0bY8II1oq?kk1=-'
    '*Z=|yZgkS5na6DADpBzV)xSR%^w=ivsa|K**PG>+=fxouTiLcnim{Snhg{Vvg5y`PL!h@G68njkR0ayH%LDITnoh`>W3(H<L%W<O'
    'z^$z#TMQ^X`B+M1$Xw%vLX?4M@U``AEBCmksW^H~dKJImB5Mr~zrem?#BnPSy2DT&<CctkMROtWk))U6y;~Cnesdvb6LSQ4L~aO^'
    'usDkkM6zOQI#j`nD$;qt4mv=qyKTjsl(T|IeRci$W_@K&W%h8kk?fQa)lXxbmTC<IM_U4vwxCBPuB&moi5%f%4RybmUgye|*!Z5Y'
    'a7ZAF68N#Q%_pkk!zUZ`BIuH<wN#(mP=#D(p=4YzP)0+tweP}7tV5tR58qlL3^>4qs2S6s^_XcEAicoOeBi5rCZF>1U;M+F#$H~)'
    'vMb=JS}lk@yLOw{%0N>A8L7uo(XmZW@g<Epg8PZWj84j^s!mEW)X#8@LA?~Mku~M%-'
    '46&&+V4vK9rHJtgv)lm$EG`xrtU2!aVk131N`P%@+gN1&(fs422$O_<Ir8s%V-~C1>~F^1bzu1+ws%^w+m51{e-'
    'CnK+E^eWF?=OXC7A~S5KYo1*egPXY5Tf1P(KB=Td*M3cQz2sE|zLQG~}OP$pk+qEo_;l%?($2`lWlRliOdwMkbD44|Sfz@MIplbG'
    '~#P+>=H!+==ARI!}Rj4a+d#;Viy>@5MiD3rwzwBdr|WU2ld=~(m=j4#cQQ-Y=1l8tC{mfF-'
    'Hc%<Y>(m%XWg^7Pm#QC0gICYllM{5BrN;LJR_m7JFlw5;$PMT^2CxpG0F7m-)urSA7<eVC<;7e=wX1<~4G3X^LFY-u_p^{)A@ia2'
    '0U;&W08WK&)@yq*1tD-'
    '(M?S0F?ywRliFV1oP5iKhNuCO1Q2Q`i9!uusfn6uP{P*O%cx43{c840e|`{bLAv|WVgyLvG2f|CL!)&$LqYeR`Tm0pm1?|lQm+7g'
    'HxnubI@pJ+a(rg{vUk{1HXMvdB9Heg$|X_AaQXG|BgZJMkIc;)i4yYgr5HDkZ8ZjDH04di4{gumqR;54z<p-'
    'w8Fw!3TIOFT}1ZRF1)Rx70(&&I_N%sd?i%&vYHAkt50R6mmT&BjwN0M!?G062YN_)CIAeu(Fa_zF|(X=sJ!U2S`(Hv52BoYv#ZhD'
    '4{;B8?fiv<<(!jnR!RbqYyr9S;!!e8%D0Mi%O=Hl1Ufz9AK8Ce_*&Ays>8LTj>Q=7L;7fc3!4lz~2WeO;Mtq6g}agZlXoUniiGv2'
    '(Wi<a5S<?MlJd-Eu%!;uV=a2$;2#no;+xn~C%UYUj@u%{hcH7%x8LiBhRKG}0&^0c9~XF*G^G#)bHvrSUxvm%i#fdxE{2UIr~wcg'
    'nP}l=CbU0+W7qC5Q#u&7;_&<}kQy52wc_m0d#dxZ8v2v#72fy{tsS{Je(VR+CCxwefi{EI#;g?g0wy$C-'
    'cPLIiSo_w(DlQkqbH{T+#vjHgZU5M~By9OV46u3@=r!DvtrVcD(WUYsA%I^)SXms)SnyYBG>e?;S6X7j&(uy#aFI&C04NaJ!FlzT'
    '{X<w9Dv!!@yr$?Q}Cm|?*!sTrgS)(Sxe2QE+efqv1tHCl7PDAhc)LHh1h);QXAGC^~3XOQh&G@!5Wkq{I*SkGVQX@)rf^!UP!Go#'
    'GZix?PIHlmzGsL<Q~cdn7MQJ2iq49)=T>Uj81^oSPRmQb9vM!KEJ+^{vyxSJL&?HGPmI6P@SJ_@D>!SjJA?Ob6|lq$}XAJjfZm;b'
    '(f&!~TaK^kMvCW+;?<UdJ!5sB?3e>56nDDMqWE6}edicx+pmSBiU0{!HNB7G>s@%SLhyot52#N)mH5JdB-2Klu-'
    '6UbKKG8DHdDcSu<9$OusFX<$NpM=5S?+X>}7>(_<Ei8X6vN?A@lcA$Rq6Z~yOoQV(AH>9s85U<PYTw(v=^lG>r}j;XA;H2=h3K6g'
    '73`eK1@ngSR-=7zArx>LTiC<F{pdxA@-P}qCqG5yQiWc5-'
    '||=vwbrEt02Bz>aXn8eVY`YmUrT?Rj9FP@Ml~!mCf=q!*)I}JZFLCMy8O`1U)>FY7bfvi8I?!(;*vH2?om{jw8t|hsllPn;?`f)>'
    '0UJilX{*ryUH4#ASQJ%oVF^|Vx;fb7Aa40sv^j4tw=v2BF(>^-'
    'yQQbp6Oo4b*4AIvW!2{uq2ddHS1dvY>C!5I&bdc0EaRL7+a&8T6SL&+Y#fyL+~XX$TFx#rqL?kTeHs%?%r5bX;F>$NftmSUjVjrv'
    '4E6Zc%1qAQ_XD=XbDfj??C)tX8N|F)2GlL+Mi>0^s4k}=CS>sS4$GtkF(WWe6`sRgZq9D`Q?^TmAqx=+o0NNKNV|id-'
    '$I}JYLpB+5}p_?x{MNwTA~Y9`Q|#Nb=*Rfw86ZJ*k>7+&FF1VOStA^Vcp?=gHUY6TlKdHGzuD!0vAx5xAX|L6^R_<Q?NmY&UIoh>'
    'DcijjSALfqyGQot`6qIhh}5BIS{CvBQoxPK-?{0s!i{n^Y-'
    'lp3}BW8ayZlf1n*$@Zri8@^i;b(3BFPtZ)yS0KT#pAV5ASMxodA01(5uc1-fV^ZMcbxN-'
    '*U`DsGY&%v@QI_+NkA5B?}ZF%DC{n^@Se;B3pb?no=oyYq9hSJzSjl<n+QZ>%uc8sJE(h{4B1GufUG(lMEa3h6c@lrU|Z8R8W8$I'
    'T74hphA+_j*lOSt-'
    'X!CPh65CE#^+}izce(xMJsq>}Wl6mT!!RNN?j#vw@1@ap#<7p<r5tC|lM}}5KIYYEX&fyS8#fXMKHi&ZJ4!Lzk0jxGpK?3p=^f$c'
    '!eRp=W61@k!AONkYIy*C*kb%7&zQ|FxzAnNbjle3l;at00WXD7_Xo9IcCBywGB~CF{{I8A$ailqkADi{kD^F)8m9I5E0K8g&a<7X'
    'Vb$nWX+jP-!@=uaYuSXv_DGRMtb`6*`FY>JmNfaC}I_-'
    '0YXpa>9i4dmP_aeZj>8{*9K=Wp&YM?$9sd>}!xBL*n!9nwa&#mdw8BZ3Temva?q`Xx#)L0U^G_+8Ee*9!qdlb}2*v>`DdJ|Ulsk#'
    'vtPm)5GH#IeDA}-p6Re!oyaW$4Fw|3Arhk;wNE_DUXDiEEzJAkIba<A#1vHw4-'
    'FIf5<n#L8DBQ!yMmV8$s+6UI8rSs|odgfsY(zD1jBbllr1dhzGzfj1PxgQITZ*VbrOgfay|13(8(_spe`*caFXf5z?|6-'
    '5|sp>FO337#MlaIGud(;(~j1x=uaeuSn@2V+aG>)VILmPSO@H=KE!UN7<mDwVkC@G}mYPWz%S^<?00v>sDKxczn<6-!`-'
    '({R)sBnP(4Y8Dvokrjao248=JujoWS~}BO;rnk-'
    '28iz<gOZkKf&N&S!`bi~3|@lJNovS?HB5o?>P@4UaWaC*7py;+OD77i&LhD@sp4G%YOe1z1!fGodGHbcXTn#l?Z5PS$uvrnjA5yU'
    'B7!SUk8r}XSr%>wAu}6As~TzDnw6SO2ZuB;V|ZTa;f5EFWaaQpud*hSTH?MK;xO|y(*A;uwTVi|45$_z-'
    '8R4?Viy=&@2LDOMCPq!!87()ZYRVjGcNVZ%njKMP2fr)d(SAu(GXB!x*T;G+Xx26=9dk-'
    'K1|!nN$I9=SPB9GU7(xb#3pg5ipzE*iebHvN`z}3(bD0P$T9(D^tCu1|LI>Zj1GfD$(^#%mh4RvV|U-'
    '+d~i*B1nI8S{mru)Qt|FSNpbkxF_!u6Y!fs({x`cy8Sia+eoc;70^)WhwaH&r)&#e;%F>y0?ep?i&=^%)J1un^-'
    '|A~zqGl#x;eXz-'
    'N~Ehy5ozZ$8d5`nLAoNSi25F?O8BACbnffdv_*MPd<>yCXt(p3rM62#$ABOZyXDA}mt7W5)EY&tCcKx<Kx$V_`u1A=9lw^2jOTAD'
    'tU2^w!8+qJ6)dJv)8ov53URvBg-VD~f7NF1gRIBN{ZW{VsdJ2TX}Qr`>I9_;<)~l}n4JFR@dD&Rb7^9&%UmbysUpg96@tU)pxz5b'
    '=M7CUv}Qv>M4+PZGg!eOKC&bM$Qf|vLL~F>WiIw**(R@KXiru6LVAHjz%;{tI#U^Cv50%*-'
    'NO?udV3NpkGJGrtYCDTIhKrYN2w>hvo6-A_oH}N(_BJ^U@=|7|E~(U-'
    'A{P<%J83FRI_QV)po_+D$}jg2MwBrBX$eRBo^XUXYw#1X(<K+?7{VlI+o3gXf8eg%D#(k${(vmqK|ge;S%BhkWDD7AQ}^IF34vCB'
    'bS4PsWD9j7)1HaI;T_!G3CIeR#Fnshq<koXeUL|De5sHSGwZp&vH-'
    '08xb&|wen9v42V^i$sc9NR>v1}!QZMwj1=}qbb@)&&8_mRGsl@jC+uTcFN=g4do+^P7t4(mQ=PTepb~%6YdLmf1dY#Lg|p(^ai<w'
    'Y-kt14$04O{tM5kscFjoyv6aGBsR)qx+l@n7aiT=Zm!}?|Sudy5wRFm(@+yUmO!4Z>XayU%A;cNb!Slg3a6cRmpyMM;#W=G1c#h<'
    'VyP}%^LF#st?Ju~vRBaF(@zKLRoVbG#LI!eWT$-'
    'Tz!lJV|PNTXA{eob5<T0KOtnZWxT;*<z_jUdLB2pw14H@z6t?)+aL+D}<SvY1h7;Bi?o&Y1gP6L*SQnfaB*r1Ql4AE;CEcKT$;|-'
    'iSm;dnpWKfa`r9P`>G`ql~lI%;qZJ8*AJdZ8gx<9M@3N?!{p4Nj;(QoHJ)z9Y8$(SBd`rvo8ZO-'
    'C$UiGN)j4N6nj>FxyAx|+sO?r>$gEoAM&M69ba;VUTW+cD8#*Sm)!g3t@!ra!eVF6#8zHjc<>LQ{G#YmEou!fQB_sSLz4X*DKZuk'
    'O*W594s5Rsh@Km^Bvwf*LOr<KI&5;FPS2GQC{M=JhXlWFXl?E>M<l_g;DIPFuN#^|?BZ(10dYowFp1PX%QX^vn!lcbsXym$Yg6D-'
    ')9CY3gr$?a0HV$p<mp&7a-Ep`{ZNpi<lJgE6$f|To0gnatkx-+|Bje)33g@5m4XQ+KFVwhPO&8sV+#&5}K&-'
    's<4ZI~k+D5c&jo}n@YdqkWHjzW5R2+$wi`k4M3uC|I%=Ta*9Uwa&>e5%4_Ri+SOOcP#G-2_-'
    'Qqgt4)1&c@!)c!VVqE(?URLXzK6o$8ELYp+E%@06-'
    'jkEfNZX`jc<ud65@z+vm`Et3`qfzw+`q#wC6N|~i%4~PBwRMLAWpjDxiOy<Ww7F9uh`ALQFD{hGjl{CTL#vofG;9LMS?s$bKT)Ji'
    'D1FY>65gMLrz^t#ssPgZsOD*9cf19&MVyVGeOg9>&J`TMnSZJj!TVC<DbB^R<ZV`dM1xYXK9B?*#p*gxLgbWY0z7*&)l5}>tO|H9'
    '?7R$|41aE=4N0k3l+$6K+Rzr+V!zmD{%+?GvwCC4f#2TkjrK7QE|>UUy^evi4i=6fbM47K%h+q`_W9bl)z3~RE}SlUjw`%fbRHg^'
    'D+}EF4u~#?8$t{E@5j@|JLt2Il+nB;QaOBN9_)R9_MeXrF40=_9Cq3Ty~3xu^Ro5FA%d2>gl4XfdT!YI0FLD0nX?tX9ZEP9wn$RY'
    '1Y4b(tVGKZB5lu@vZ3jVrn=CLAiHskB>5`OSXlo=@2T!jVizsZo#Z^i6k<dfqc8v?5ZlVak09GNO}Z*h@+D3P&+^c;UQ_6>Jk~{^'
    'Bb|&`k|etQEMBZ3`{q+chQ!q{-'
    '#9n6l<(O^HN!fO1+m=NUe+Y>SFk>@lsz_>^bNBoR{=Q%T*_cNQ*MvQHu+_>GH;TF?VSNs&8jh$%o#g)qQc#^sb-WFEd2g-'
    'e0>C*H?4*tU0hwCE}13wS-q8Swt)s+(ueORKNPE;MO8IRzQ&7=Iqg;#F$a-c1o*3;i(%h}nd{Evxa-'
    '}yHG!&f*0t0>ZiqVSfb_w}b*FT2a^>_?+q!x`bpAv8G_qnN$aI(GA+vEs`43yBqI9#T%*BZ600000$5(Vz=kOu^00H7v%$eT-'
    'Xcg4gvBYQl0ssI200dcD'
)

class NativeDaaReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pack=base64.b85decode(PACK);assert hashlib.sha256(pack).hexdigest()==PACK_SHA256
        cls.raw=lzma.decompress(pack);assert hashlib.sha256(cls.raw).hexdigest()==RAW_SHA256

    def replay(self,mutate=None):
        raw=self.raw
        if mutate is not None:
            rows=[json.loads(line)for line in raw.splitlines()];mutate(rows)
            raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode()for row in rows)
        with tempfile.TemporaryDirectory(prefix='w1-daa-reader-')as directory:
            path=Path(directory)/'native.stdout';path.write_bytes(raw);return reader.read(path)

    def reject(self,mutate):
        with self.assertRaises(ValueError):self.replay(mutate)

    def test_original_native_vector(self):
        v=self.replay();self.assertEqual(v['full_proofs_replayed'],36)
        self.assertEqual(v['greatest_branch_work'],173);self.assertEqual(v['total_forest_work'],196)
        self.assertEqual(v['native_search_attempts'],190);self.assertFalse(v['O03_closed'])

    def test_forest_is_not_heaviest_chain(self):
        self.reject(lambda rows:rows[-1].update(active_chainwork=196))

    def test_no_qualification_promotion(self):
        self.reject(lambda rows:rows[-1].update(O03_closed=True))

    def test_target_must_match_original_daa(self):
        def change(rows):
            r=next(r for r in rows if r['kind']=='admitted-block')
            r['target']='00'*31+'01'
        self.reject(change)

    def test_full_proof_really_replayed(self):
        def change(rows):
            r=next(r for r in rows if r['kind']=='admitted-block');b=bytearray.fromhex(r['packet_hex'])
            offset=320+4+2*4096*4;v=int.from_bytes(b[offset:offset+4],'little')
            b[offset:offset+4]=((v+1)%reader.p.work_oracle.Q).to_bytes(4,'little');r['packet_hex']=b.hex()
        self.reject(change)

    def test_original_miss_count_cannot_be_labeled_retained(self):
        def change(rows):next(r for r in rows if r['kind']=='admitted-block').update(unsuccessful_proof_bytes_retained=True)
        self.reject(change)

    def test_partial_vector_never_passes(self):
        self.reject(lambda rows:rows.pop())

if __name__=='__main__':unittest.main()
