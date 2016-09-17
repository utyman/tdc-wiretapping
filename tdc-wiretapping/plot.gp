set term png font "arial,8" size 500,500
set yrange [0:max]
set output filename
set boxwidth 0.5
set style fill solid
set title "Información por Símbolos"
set xtics rotate
set bmargin 8
plot "data.dat" using 1:3:xtic(2) with boxes title "I(S)", entropy with lines title "H(S)", maxentropy with lines title "H_max(S)" 
