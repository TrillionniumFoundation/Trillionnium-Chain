# V5 fixed-arm T1/H8 observations

All values are milliseconds per accepted winner, computed as complete producer sums divided by accepted winners. The four named columns are preregistered implementations; lowest columns select one aggregate fixed arm after all eight cohorts and are descriptive observations. All 17 arms in every cost cell are retained in full-cost-grid.json. Controls are excluded.

## arm64: T1 / H8

| Material | Dense CPU / wall | Sparse CPU / wall | Rank8 CPU / wall | Batch4 CPU / wall | Lowest observed CPU fixed arm | Lowest observed wall fixed arm |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| zero | 11.177221 / 11.175377 | 11.168652 / 11.166103 | 11.163744 / 11.161044 | 13.591741 / 4.733355 | blocked-zero 7.920730 | full-limb-rank8-batch4-lazy 4.733355 |
| rank-one | 8.988479 / 8.986636 | 9.005488 / 9.003664 | 8.983389 / 8.981658 | 11.086766 / 4.344901 | prepared-structured 7.911629 | full-limb-rank8-batch4-lazy 4.344901 |
| rank-two-left | 10.188718 / 10.186960 | 10.204509 / 10.202413 | 10.182476 / 10.180467 | 12.520022 / 4.758563 | prepared-generic 8.965081 | full-limb-rank8-batch4-lazy 4.758563 |
| rank-four-left | 8.451730 / 8.449849 | 8.469912 / 8.468198 | 8.450196 / 8.448774 | 10.502339 / 3.960739 | prepared-generic 7.454034 | full-limb-rank8-batch4-lazy 3.960739 |
| rank-eight-left | 11.639536 / 11.637434 | 11.638227 / 11.635730 | 11.618332 / 11.615965 | 14.131400 / 5.720156 | prepared-generic 10.239467 | full-limb-rank8-batch4-lazy 5.720156 |
| rank-four-right | 10.563185 / 10.561137 | 10.586090 / 10.584528 | 10.555927 / 10.554515 | 12.974666 / 4.838607 | prepared-generic 9.305392 | full-limb-rank8-batch4-lazy 4.838607 |
| rank-nine-left | 9.726684 / 9.724608 | 9.749728 / 9.747744 | 9.736997 / 9.735015 | 12.180689 / 5.287155 | prepared-generic 8.566498 | full-limb-rank8-batch4-lazy 5.287155 |
| full-rank-field | 11.238586 / 11.237577 | 11.255491 / 11.253054 | 11.242227 / 11.239490 | 13.700687 / 5.660448 | prepared-generic 9.904761 | full-limb-rank8-batch4-lazy 5.660448 |
| sparse-diagonal | 10.717276 / 10.714887 | 10.703822 / 10.702195 | 10.717083 / 10.714801 | 13.092216 / 5.198812 | prepared-structured 9.436174 | full-limb-rank8-batch4-lazy 5.198812 |
| one-zero-rank-one | 11.051387 / 11.049532 | 11.035904 / 11.033805 | 11.040973 / 11.038679 | 13.538861 / 5.233374 | prepared-structured 9.737915 | full-limb-rank8-batch4-lazy 5.233374 |
| continuity-maintenance-v1 | 8.847335 / 8.845791 | 8.857852 / 8.856581 | 8.845214 / 8.843400 | 11.040417 / 4.244853 | maintenance-limb 7.437106 | full-limb-rank8-batch4-lazy 4.244853 |

## x64: T1 / H8

| Material | Dense CPU / wall | Sparse CPU / wall | Rank8 CPU / wall | Batch4 CPU / wall | Lowest observed CPU fixed arm | Lowest observed wall fixed arm |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| zero | 10.002930 / 9.999333 | 9.994125 / 9.990495 | 9.989185 / 9.986445 | 17.562191 / 5.262023 | blocked-zero 9.518142 | full-limb-rank8-batch4-lazy 5.262023 |
| rank-one | 8.182537 / 8.179181 | 8.197281 / 8.194520 | 8.167986 / 8.165102 | 14.291245 / 4.271457 | full-limb-rank8-lazy 8.167986 | full-limb-rank8-batch4-lazy 4.271457 |
| rank-two-left | 9.155194 / 9.152944 | 9.154081 / 9.151589 | 9.137944 / 9.134958 | 16.384342 / 4.864102 | full-limb-rank8-lazy 9.137944 | full-limb-rank8-batch4-lazy 4.864102 |
| rank-four-left | 7.565909 / 7.563593 | 7.568784 / 7.567468 | 7.581450 / 7.578865 | 13.436504 / 4.167226 | full-limb-dense-lazy 7.565909 | full-limb-rank8-batch4-lazy 4.167226 |
| rank-eight-left | 10.396195 / 10.392264 | 10.432819 / 10.426139 | 10.380025 / 10.374372 | 18.424354 / 5.462041 | full-limb-rank8-lazy 10.380025 | full-limb-rank8-batch4-lazy 5.462041 |
| rank-four-right | 9.476173 / 9.473243 | 9.457459 / 9.455109 | 9.529814 / 9.544620 | 16.912112 / 5.033333 | full-limb-sparse-lazy 9.457459 | full-limb-rank8-batch4-lazy 5.033333 |
| rank-nine-left | 8.688343 / 8.684990 | 8.691086 / 8.687818 | 8.689756 / 8.686543 | 15.675740 / 4.741099 | full-limb-dense-lazy 8.688343 | full-limb-rank8-batch4-lazy 4.741099 |
| full-rank-field | 10.240217 / 10.236758 | 10.252724 / 10.249489 | 10.227075 / 10.223229 | 17.814269 / 5.302557 | full-limb-rank8-lazy 10.227075 | full-limb-rank8-batch4-lazy 5.302557 |
| sparse-diagonal | 9.601595 / 9.599020 | 9.616061 / 9.612870 | 9.600023 / 9.596819 | 17.087315 / 5.124928 | full-limb-rank8-lazy 9.600023 | full-limb-rank8-batch4-lazy 5.124928 |
| one-zero-rank-one | 9.905304 / 9.902341 | 9.860383 / 9.856798 | 9.873310 / 9.870157 | 17.577529 / 5.183300 | full-limb-sparse-lazy 9.860383 | full-limb-rank8-batch4-lazy 5.183300 |
| continuity-maintenance-v1 | 7.939432 / 7.937231 | 7.927185 / 7.924731 | 7.921473 / 7.918627 | 14.311804 / 4.311891 | full-limb-rank8-lazy 7.921473 | full-limb-rank8-batch4-lazy 4.311891 |
