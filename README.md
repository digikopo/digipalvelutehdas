# OKM toimialan API- ja palvelukehitysstrategia

OKM toimialana tarvitsee jalkautuksen sisältävän API strategian osana arkkitehtuurisuunnittelua. Strategioita on jo monia kuten esimerkiksi älystrategia, mutta niiden vika on että ne jäävät paperitiikereiksi…tai oikeastaan bittitiikereiksi makaamaan palvelimien ja kovalevyje nurkkiin.

Lähtökohta tulee olla palvelujen rakentaminen osaksi kansallista palveluarkkitehtuuria. Kaikkien toimien tulee edistää tätä tavoitetta ja madaltaa kynnystä innovoida uusia tapoja käyttää digitalisoituvaa tietoa entistä tehokkaammin ja monipuolisemmin.

Teollinen internet, josta paljon puhutaan on nimenä harhaanjohtava. Kyse on teollisesta vallankumouksesta jonka vaikutukset ulottuvat koko yhteiskuntaan ja samat periaatteet tulevat vaikuttamaan jokapäiväiseen elämäämme. Emme siis opetussektorina voi tuudittautua uneen ja olla ottamatta ympärillä tapahtuvaa muutosta huomioon. Teollisen internetin yksi keskeisin elementti on webpohjaiset rajapinnat (API, Application Programmin Interface).

## Rajapintojen kehittäminen avoimella lähdekoodilla

Avoimet rajapinnat ovat hyvä mutta riittämätön lähtökohta API strategialle. Rajapinnat tulee tehdä avointa lähdekoodia käyttäen. Pelkkien avoimien rajapintojen edistäminen ei riitä. Vaikka rajapinnat ovat avoimia ja kaikkien käytössä, myös rajapinnat muuttuvat käyttäjien tarpeiden mukaisesti. Rajapinnan kehittäminen puolestaan vaatii tuntemusta taustajärjestelmästä ja suljetun komponentin kohdalla se tieto on vain tuotteen omistajalla. Tämä puolestaan johtaa siihen tilanteeseen, että suljetun tuotteen omistaja voi mielivaltaisesti päättää mitä muutoksia rajapintaan tehdään jos tehdään ollenkaan. Toiseksi, tämä tilanne estää muutosten kehittämisen vapaan kilpailuttamisen kyseisen komponentin toteuttamien ominaisuuksien osalta. Näin ollen päädytään lähelle perinteistä vendor lock-in tilannetta. Kun kukaan ei tiedä mitä muutosten tekeminen vaatii, voi tuotteen omistaja mielivaltaisesti määritellä kulut tai todeta ettei haluttuja muutoksia voi tehdä.
