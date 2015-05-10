# OKM KOPO toimialan API- ja palvelukehitysmalli

| Otsikko |               |
| ------------- |:-------------:| 
| Vastuuhenkilö      | Jarkko Moilanen, [@kyyberi](twitter.com/kyyberi)  |
| Versio      | 0.2 |
| Päiväys      | 29.4.2015 |
---


OKM KOPO toimialana tarvitsee jalkautuksen sisältävän API strategian osana arkkitehtuurisuunnittelua. Strategioita on jo monia kuten esimerkiksi älystrategia, mutta niiden vika on että ne jäävät paperitiikereiksi…tai oikeastaan bittitiikereiksi makaamaan palvelimien ja kovalevyjen nurkkiin. Lähtökohta tulee olla palvelujen rakentaminen osaksi kansallista palveluarkkitehtuuria. Kaikkien toimien tulee edistää tätä tavoitetta ja madaltaa kynnystä innovoida uusia tapoja käyttää digitalisoituvaa tietoa entistä tehokkaammin ja monipuolisemmin.

Tavoitteet ja linjaukset toiminnalle löytyy [Tim O’Reillyn digitaalisen hallinnon pääkohdista](http://chimera.labs.oreilly.com/books/1234000000774/ch02.html#lesson_1_open_standards_spark_innovation): 
* Tue avoimia standardeja.
* Suunnittele palvelut tukemaan aktiivista osallistumista.
* Tee asioiden kokeilemisesta helppoa.
* Opi ulkopuolisilta osaajilta.
* Luo edistymisen mittaamisen kulttuuri.
* Rakenna yksinkertaisia digitaalisia palveluita, joita on helppo kehittää

Teollinen internet, josta paljon puhutaan on nimenä harhaanjohtava. Kyse on teollisesta vallankumouksesta jonka vaikutukset ulottuvat koko yhteiskuntaan ja samat periaatteet tulevat vaikuttamaan jokapäiväiseen elämäämme. Teollinen internet (joskus myös esineiden internet < engl. The Internet of Things tai IoT) viittaa yksilöitävissä olevien sulautettujen tietokoneiden kaltaisten järjestelmien yhteenliitokseen olemassaolevan internetin infrastruktuurissa. Teollisuuden murroksessa perinteisissä teollisuustuotteissa aletaan hyödyntää internetiä, nanotekniikkaa sekä muuta viestintä- ja tietotekniikkaa. Teollisessa internetissä esineille annetaan tunnistettava identiteetti ja ne alkavat viestiä keskenään. Verkkoon kytkeytyvät laitteet voivat olla esimerkiksi teollisuus-, koti-, palvelu- tai hoivarobotteja. Emme siis opetussektorina voi tuudittautua uneen ja olla ottamatta ympärillä tapahtuvaa muutosta huomioon. Teollisen internetin yksi keskeisin elementti on webpohjaiset rajapinnat (API, Application Programming Interface).

Toimialan julkisin varoin tuotetusta tiedosta on tehtävä avointa. Tieto on jaettava ilmaiseksi ja erityistä huomiota on kiinnitettävä julkisen tiedon rajapintoihin (API). Tieto, joka ei ole yksinkertaisesti ja automaattisesti haettavissa ja hyödynnettävissä, ei ole kovin arvokasta digitalisaation edistämisessä. 

[JHS-järjestelmän mukaiset suositukset](http://www.jhs-suositukset.fi) koskevat valtion- ja kunnallishallinnon tietohallintoa. Sisällöltään JHS voi olla julkishallinnossa käytettäväksi tarkoitettu yhtenäinen menettelytapa, määrittely tai ohje. JHS-järjestelmän tavoitteena on parantaa tietojärjestelmien ja niiden tietojen yhteentoimivuutta, luoda edellytykset hallinto- ja sektorirajoista riippumattomalle toimintojen kehittämiselle sekä tehostaa olemassa olevan tiedon hyödyntämistä. Suosituksilla pyritään myös minimoimaan päällekkäistä kehittämistyötä, ohjaamaan tietojärjestelmien kehittämistä ja saamaan aikaan hyviä ja yhdenmukaisia käytäntöjä julkishallintoon ja erityisesti julkisten organisaatioiden tietohallintoon. Suositukset hyväksyy julkisen hallinnon tietohallinnon neuvottelukunta [JUHTA](https://wiki.julkict.fi/julkict/juhta) ja niiden laatimista ohjaa JUHTAn alainen JHS-jaosto. OKM:n tulee aktiivisesti osallistua JHS työhön, hyödyntää olemassa olevaa ja viedä omia hyviä käytäntöjään osaksi JHS-järjestelmää.  

Malli sisältää 7 periaatetta ja toimintoa: 

1. Tilannekuvahuone
2. Keskitetty kehitysympäristö ja versionhallinta
3. Rajapinnat fokuksessa
   * kehittäminen avoimella lähdekoodilla
   * Yhdenmukaisesti käyttäytyvät rajapinnat
   * Keskitetty rajapintojen hallinta
4. Asiakaslähtöisyys
5. Avoimen tuotteen hallintamalli
6. Iteratiivista ketterää kehitystä 
7. Palvelukehityksen portaali


## 1. Tilannekuvahuone
Tällä hetkellä tieto ja ymmärrys palvelukehityksen kokonaiskuvasta on heikko. Osastot ja virastot tekevät omia ratkaisujaan. Keskustelu osastojen välillä on lisääntynyt, mutta siltikään ei ole tapaa pitää yllä yhteistä tilannekuvaa. Näin ollen johdolla ei ole tietoa, jonka pohjalta tehdä päätöksiä kokonaistaloudellisesti järkevällä tavalla. 

Ministeriössä tulee olla palvelukehityksen tilannekuvahuone, jossa toimialan (ml Karvi, YTL) keskeiset projektipäälliköt ja hankepäälliköt sekä arkkitehdit tapaavat säännöllisesti jakaakseen tietoa ja koordinoidakseen kehitystä. Nykyinen tilannekuvahuone on muodostunut huoneeseen K237 Meritullinkatu 10. Kasvokkaisia kohtaamisia ei voi korvata millään tekniikalla. Fyysinen tapaamispaikka on sosiaalisuuden ja sosiaalisten suhteiden rakentamisen ja ylläpidon kannalta välttämätön. Maslow sen aikanaan jo totes. 

Tilannekuvan luomiseen ja ylläpitämiseen saa osallistua jokaiselta osastolta yksi henkilö. Ryhmä tapaa joka toinen viikko. Palaveri on maksimissaan tunti. Tilannekuvahuoneen seinällä on kiinnitettynä 5 vaiheeseen projekteja ja niiden A4 kokoisia kuvauksia. Prosessina alla olevan kuvan tyyppinen

![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/okm-tilannehuone-seina-2.png)

Tarkempi kuvaus tilannehuoneen järjestelyistä ja käytännöistä on [kuvattu omassa tiedostossa](https://github.com/digiokm/palvelukehitys/blob/master/tilannekuvahuone.md)

**Toimenpiteet**
* Ministeriössä jatketaan ja laajennetaan tilannehuoneen käyttöä osana tilannekuvan muodostamista ja ylläpitoa. 
* Kutsutaan mukaan Karvi ja YTL 
* Kehitetään [projektien canvas-mallia](https://github.com/digiokm/palvelukehitys/blob/master/tilannekuvahuone.md#2-suunnittelu) ja prosessia osana muuta kehitystä == käytetään mallia osana toimintaa.
* Otetaan käyttöön [3/30 -malli ja palvelukehitystehdas](https://github.com/digiokm/palvelukehitys/blob/master/palvelukehitystehdas.md) 


## 2. Keskitetty kehitysympäristö ja versionhallinta

Kehityksessä tulee käyttää aina kun mahdollista JulkICTLab ympäristöä tai sen johdannaista. Valtiovarainministeriö käynnisti julkisen hallinnon palvelu- ja innovaatiotoiminnan kehittämisalustan -toteutusprojektin 2013 osana julkisen hallinnon ICT-strategian toimeenpanoa. JulkICTLab -alustan tavoitteena on tukea julkisen hallinnon ICT-ratkaisuja ja toimintamalleja kehittävien ekosysteemien syntyä yhteistyössä alan toimijoiden kanssa ja tarjota kehittämislaboratorio (ml. ympäristö ja työkalut) toiminnan tueksi. JulkICTLab kytkeytyy läheisesti kansalliseen avoimen tiedon ohjelmaan, koska palvelu- ja innovaatiotoiminnassa on tarkoitus pyrkiä hyödyntämään myös julkisen hallinnon avautuvia tietoaineistoja. Lab vietiin tuotantokäyttöön 2014 ja vuoden 2015 toteutetaan jatkokehittämistoimenpiteet. JulkICTLab on toteutettu yhteistyössä liikenne- ja viestintäministeriön rahoittaman innovaatioalustan (FORGE) kanssa.

Lisäksi OKM:n toimialana tulee keskittää lähdekoodinhallinta Github palveluun tai vaihtoehtoisesti käyttää palveluavastaavaa ratkaisua Gitlab, joka löytyy jo valmiiksi JulkICTLabista. Github palvelun käyttöä puoltaa se fakta, että kehittäjät ovat jo siellä. Github palveluna on avoimen lähdekoodin yhteisön de facto palvelu ja siten kehittäjäpohja laaja. Eriytymällä omaan Gitlab palveluun eristämme itsemme muusta kehittämisyhteisöstä. On kuitenkin tilanteita, jolloin Gitlab käyttö opn perusteltua. Oletusarvoisesti kuitenkin käytetään Github palvelua. 

**Toimenpiteet**
* Ministeriössä KOPO ottaa Githubin käyttöön ja keskittää kehitysprojektiensa versionhallinnan Github palveluun oman organisaation alle. 
* Github organisaatiolle nimetään vastaava henkilö
* Kehitetään github ympäristöön yhtenäinen MVP projektimalli ([canvas](https://github.com/digiokm/palvelukehitys/blob/master/tilannekuvahuone.md#2-suunnittelu) + käytännöt). 
* Github ympäristöä ja sen sisältämää tietoa hyödyntävän reaaliaikatilannekuvanäkymän luominen organisaatioittain (OKM, Karvi, YTL). Mahdollistaa tiedon esittämisen kuvaajina ja toiminnan mittaamisen. 

## 3. Rajapinnat fokuksessa 

### Kehittäminen avoimella lähdekoodilla

Avoimet rajapinnat ovat hyvä mutta riittämätön lähtökohta API strategialle. Rajapinnat tulee tehdä avointa lähdekoodia käyttäen. Pelkkien avoimien rajapintojen edistäminen ei riitä. Vaikka rajapinnat ovat avoimia ja kaikkien käytössä, myös rajapinnat muuttuvat käyttäjien tarpeiden mukaisesti. Rajapinnan kehittäminen puolestaan vaatii tuntemusta taustajärjestelmästä ja suljetun komponentin kohdalla se tieto on vain tuotteen omistajalla. Tämä puolestaan johtaa siihen tilanteeseen, että suljetun tuotteen omistaja voi mielivaltaisesti päättää mitä muutoksia rajapintaan tehdään jos tehdään ollenkaan. Toiseksi, tämä tilanne estää muutosten kehittämisen vapaan kilpailuttamisen kyseisen komponentin toteuttamien ominaisuuksien osalta. Näin ollen päädytään lähelle perinteistä vendor lock-in tilannetta. Kun kukaan ei tiedä mitä muutosten tekeminen vaatii, voi tuotteen omistaja mielivaltaisesti määritellä kulut tai todeta ettei haluttuja muutoksia voi tehdä.

Lisäksi julkinen sektori on velvoitettu tuottamaan avointa tietoa ja edistämään keinoja uudelleenkäyttää tietoa. Näin ollen tulee huomioida rajapintoja ja palveluita kehitettäessä avoimen tiedon tarpeet. Toimialan julkisten toimijoiden tulee edistää avoimen tiedon määrän lisäämistä ja tiedon laadun parannusta. 

**Toimenpiteet ja suositukset**
* Sovelletaan [JHS 189](http://docs.jhs-suositukset.fi/jhs-suositukset/JHS189/JHS189.html):a rajapintatoteuksien tilaamisessa ja tuotannossa. 
* Avoimen tiedon laajamittainen soveltaminen palveluissa [JHS 169](http://docs.jhs-suositukset.fi/jhs-suositukset/JHS169/JHS169.html)
* Rajapintojen kehityksessä käytetään mahdollisuuksien mukaan [Design First mallia](https://github.com/digiokm/palvelukehitys/blob/master/api-design-first.md). 

### Yhdenmukaisesti käyttäytyvät rajapinnat

Rajapintojen tulee olla tarkoitukseen sopivia. Monesti kevyet teknologiat kuten JSON ja REST ovat hyvä lähtökohta ja niitä tuleekin harkita ensimmäisenä vaihtoehtona. Vasta perustellusti voi käyttää muita teknologioita kuten XML ja SOAP. Rajapintojen tulee rakentua ja käyttäytyä loogisesti samalla lailla. Tämä edistää ja nopeuttaa rajapintojen käyttöönottoa palveluita kehitettäessä. Esimerkiksi Kun kehittäjä oppii että opetussektorin rajapintojen virhetilanteidenkäsittely menee tyypillisesti yhdellä ja samalla tavalla, ei kehittäjän tarvitse opetella tai implementoida omassa ratkaisussaan koodia uudelleen vaan hän voi uudelleenkäyttää aiemmin opittua ja tuotettua. 

Tarkennuksena mainitatkoon, että tarkoitus ei ole pakottaa kaikkia tekemään rajapinnan implementaatio samalla koodilla tai käyttäen samoja REST- kutsuja. Tarkoitus on standardoida tavat miten rajapinnat suunnitellaan ja toteutetaan. 

**Toimenpiteet ja suositukset**
* Määrittää ja ottaa käyttöön [API parhaat käytännöt](https://github.com/digiokm/api-standards) toimialan kehitystä teetettäessä. 

### Keskitetty rajapintojen hallinta
 
Toimialalla on jo useita REST pohjaisia rajapintoja muun muassa opintopolku järjestelmässä. Lisää palveluita ollaan kehittämässä, kuten esimerkiksi todennetun osaamisen rekisteri (TOR). Rajapintoja tulee väistämättä lisää ja suunta onkin laajasti rajapintoja hyödyntäviä palveluita kohti (kts kuva alla). Digitaaliset palvelut tyypillisesti käyttävät useaa rajapintaa kerätäksen tarvittavat tiedot, jotta voivat palvella asiakasta tarkoituksenmukaisesti pompottamatta digitaaliselta "luukulta" toiselle esittäen tiedot yhdessä näkymässä.

Palveluväylässä on rajapintojen hallinta, mutta kaikki rajapinnat OKM toimialalla eivät käytä palveluväylää. Eikä ole tarkoituksenmukaista edes pakottaa kaikkia käyttämään palveluväylää. Ainakaan avoimen tiedon rajapinnat tulee eriyttää palveluväylästä ainakin aluksi. 

Näin ollen tulee perustaa keskitetty rajapintojen hallintapalvelu ainakin avoimille rajapinnoille. Keskitetty rajapintojen hallinta liittyy tuotteenhallintaan, jonka malli puolestaan on määritelty VTT:n kehittämässä avoimen tuotteen hallintamallissa.

![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/keskitetty-api-hallinta.png)

### OKM case
![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/keskitetty-api-hallinta-okm.png)

Hallintaratkaisu tulisi olla koko toimialan yhteinen ja näin keskittämällä saataisiin säästöjä. Mikäli erilaiset toimijat keskittävät rajapintojen hallinnan yhteen (kahdennettuun ja varmistettuun) API:en hallintapalveluun, nousee rajapintojen hyödynnettävyys huomattavasti. Silloin palvelujen kehittäjät löytävät tarvitsemansa tiedot ja kehittäjäyhteisön yhdestä paikasta. 

**Toimenpiteet ja suositukset**
* Perustaa koko toimialan käyttöön yhteinen API:en hallintaratkaisu (ei vain julkiselle sektorille, kaupallisille tahoille maksullinen) 
* Sovittaa API:en hallinta osaksi avoimen tuotteen hallintamallia osana API hallintamallin kehittämistä. 

## 4. Asiakaslähtöisyys

Toinen ohjaava arvo on design lähtöisyys. Palveludesign on jo jonkin aikaa ollut selkeästi nousussa osittain siitä syystä että se nostaa asiakkaan keskiöön. Kokeilukulttuuri ja asiakkaiden osallistaminen kehittämiseen ovat tärkeä osa digitalisaatiota.

Hyviä ja käytettyjä palveluita ei luoda ilman asiakkaan kuulemista. Asiakas tulee ottaa design prosessiin mukaan niin aikaisin kuin mahdollista. Sama pätee rajapintoihin. Rajapintojen asiakas vain on eri kuin palvelujen asiakas. Palvelujen asiakas on Matti tai Maija Meikäläinen, joka palveluväylän kautta selaimella hoitaa arkensa asioita sinne luotujen palvelujen avulla. 

Rajapinnan asiakas on kehittäjä, se taho joka puolestaan rakentaa Matille ja Maijalle palvelujen käyttöliittymät ja logiikat palveluväylään. Rajapinta-asiakasta houkutetellaan kehittähäportaalilla, josta löytyy ajantasaiset dokumentaatiot, koodiesimerkit, kehityskirjastot (SDK:t) erilaisille alustoille ja mahdollisuus olla yhteydessä kehittäjäyhteisön kanssa sekä rajapintojen kehittäjien kanssa. Rajapinnan kehittämistä on kuvattu tarkemmin kohdassa "Avoimen tuotteen hallintamalli" 

**Toimenpiteet**
* Palvelujen loppukäyttäjä tulee ottaa mukaan kehitysprosessiin alusta asti
* Perustetaan yhteinen digitaalinen tila: [https://digipalvelutehdas.slack.com](https://digipalvelutehdas.slack.com)
* Rajapintojen suunnittelussa on API:n asiakkaat eli palvelukehittäjät ottaa mukaan alusta asti
* Tuotokset mukaan lukien suunnitelmat tulevat avoimesti PDF muodossa Github palveluun
* Tulee aktiivisesti kehittää ja ottaa käyttöön vuorovaikutustyökaluja ja menetelmiä kuten avoimet online palaverit 

## 5. Avoimen tuotteen hallintamalli

Kehittämisen konseptina tulee hyödyntää Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa. Avoimen tuotteen hallintamalli määrittelee säännöt, joilla voidaan perustaa julkisen hallinnon organisaatioille käyttäjäyhteisö avoimen lähdekoodin ohjelmistotuotteen kehittämistä, ohjausta ja hallintaa varten. Malli selkeyttää mm. tuotteen omistajuutta, osapuolten vastuita sekä palvelun ylläpidon ja kehittämisen ohjausta. VTT:n luomaa mallia pyritään soveltamaan kaikissa JulkICT:n projekteissa, joissa tuotetaan palveluja avoimella lähdekoodilla. Kuten aiemmin on todettu asiakkuuksia on ainakin kahden tyyppisiä, joista rajapinnan asiakas on kehittäjä. Rajapinta tulee siis nähdä palveluna siinä missä Matti ja Maija Meikäläisen käyttämät palveluväylän näkymät. Rajapinta on tuote ja sen kehittämiseen tulee käyttää myös Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa.

Avoimen tuotteen hallintamallia tulee kehittää edelleen yhteistyössä VTT:n ja muiden tahojen kanssa. Mallia tulee kehittää siten, että se ottaa huomioon rajapintojen kehittämisen erityispiirteet. [Desing First -malli](https://github.com/digiokm/palvelukehitys/blob/master/api-design-first.md) on yksi tapa nähdä rajapintojen kehittämisen malli.

Tulee lisäksi ottaa käyttöön kontribuutiosopimukset (Contributor license agreements). Tyypillisesti niitä on ainakin kahta tyyppiä: yksi yksittäisille henkilöille ja toinen yhteisöille/yrityksille. Ideaalitilanteessa julkisella sektorilla olisi yhteiset kontribuutiosopimukset, mutta tässä vaiheessa OKM KOPO ottaa käyttöön omat sopimukset (JURISTIEN TARKASTETTAVA NÄMÄ)

* yksityishenkilöille [CLA](https://github.com/diGIKOPO/digipalvelutehdas-konsepti/blob/master/PDF/ha-cla-e-v1.pdf)
* yrityksille [CAA](https://github.com/digiKOPO/digipalvelutehdas-konsepti/blob/master/PDF/ha-caa-e-v1.pdf)


**Toimenpiteet**
* Hyväksytään CLA:t käyttöön juristien tekemän tarkastuksen jälkeen. 
* Otetaan Design First prosessi käyttöön ja sovitetaan avoien tuotteen hallintamalliin
* Avataan yhteistyö VTT ja VM kanssa avoimen tuotteen hallintamallin sovittamisesta Palvelukehitystehdas konseptiin

## 6. Iteratiivista ketterää kehitystä

Kehitystä tulee kuvata sanat osallistava, avoin, ketterä ja kokeilu. Massiiviset yli vuoden mittaiset rajapintojen kehitysprojektit tulee kieltää. Sen sijaan tulee kehittää kokeilukulttuuria ja tarvittaessa sisällyttää Avoimen tuotteen hallintamalliin. Digitalisaatiosta saadaan paras hyöty, kun yhteiskunnan kaikki prosessit suunnitellaan kokonaan uudella digitaalisuuteen sopivalla tavalla. Lisäksi tarvitaan kokeiluja eikä loppuun saakka hiottuja täydellisiä suunnitelmia. Toteutus tulee olla MVP tyyppiseen minimaalisen toteutukseen perustuvaa, jolloin tehdään vain välttämättömin osuus. Syntynyt tuotos testataan välittömästi loppukäyttäjillä ja saadun palautteen mukaan jatketaan kehitystä. Toisin sanoen kehitys tulee tapahtua avoimesti alussa raakileita ja keskeneräistä (mutta toimivaa) tuotosta hyväksikäyttäen. 

Minimum Viable Product (MVP) – Pienin Mahdollinen Tuote, jota edustaa mikä tahansa, joka auttaa seuraavan oppimisaskeleen ottamisessa. MVP:nä voi toimia esimerkiksi asiakashaastattelut tai ihmisen tekemisellä simuloitu tuote tai palvelu. Toki MVP:n roolin ottaa usein myös varhainen versio tavoitellusta tuotteesta. Tällöin on kuitenkin varmistettava, että tuotetta aidosti kehitetään vain seuraavan vaiheen testauksessa välttämättömien toimintojen verran. Tuotteen kehittäjällä on usein iso kynnys viedä asiakkaalle pelkkä raakile, mutta juuri näin tulee toimia edellyttäen että tällä kyetään seuraavan vaiheen opit keräämään.

**Toimenpiteet**
* ....


## 7. Palvelukehitystehdas -portaali

Keskitetty rajapintojen hallintapalvelusta on osa laajempaa kokonaisuutta, josta löytyy myös ajantasaiset rajapintojen dokumentaatiot, valmiit koodiesimerkit rajapintojen hyödyntämiseen, valmiit ohjelmistokomponenttikirjastot eri käyttöjärjestelmille (SDK), hiekkalaatikko API:en kokeilemiseen ja mahdollisuus vuorovaikutukseen kehittäjäyhteisön kanssa. Tässä kohdin tulee hyödyntää FORGE alustaa ja yhteisöä.

[Portaali](https://github.com/digiokm/palvelukehitys/blob/master/palvelukehitysportaali.md) tarjoaa rajapintojen asiakkaille eli palvelukehittäjille yhden pisteen, josta tieto ja rajapinnat löytyvät. Tämä puolestaan selkeyttää ja nopeuttaa palvelukehitystä, joka kuten aiemmin on todettu tulee entistä enemmän pohjautumaan webpohjaisten rajapintojen hyödyntämiseen. 

Osana [portaalin](https://github.com/digiokm/palvelukehitys/blob/master/palvelukehitysportaali.md) toimintaa on kontribuutiolisenssisopimuksien hallinta. CLA tarvitaan, koska sillä suojataan kaikkien tulevaisuutta, mutta ensisijaisesti projektia. 

```CLAs simply shift legal blame for any patent infringement, copyright infringement, or other bad acts from the project (or its legal entity) back onto its contributors....There are three important components to any contributor agreement: an assertion that the contributor has the right to contribute the code, a statement of actual contribution, and consent that the code may be distributed under the project's licenses. ```

Lue myös:
* https://julien.ponge.org/blog/in-defense-of-contributor-license-agreements/ 
* https://www.clahub.com/pages/why_cla
* https://opensource.com/law/11/7/trouble-harmony-part-1

CLA:n käytössä olennaista on kontribuutiota hyväksyttäessä tarkistaa, että kyseinen taho on allekirjoittanut CLA sopimuksen. Tyypillisesti yhdistävänä tekijänä voidaan käyttää CLA allekirjoituksessa mainittua sähköpostiosoitetta ja github tilin sähköpostisoitetta. Toisin sanoen vain github prosessien kautta tulevat kontribuutiot voidaan hyväksyä, jotta on riittävä varmuus kontribuoijasta. Esimerkki https://contribute.jquery.org/CLA/  

Lue lisää [palveluportaalin määrittelystä](https://github.com/digiokm/palvelukehitysportaali/tree/master)

**Toimenpiteet**
* Perustetaan palvelukehityksen portaali PoC vuoden loppuun mennessä
* määritellään PoC minimum viable tyyppisesti
* Projekteissa tuotetut API:t ja niiden dokumentaatiot tulee lisätä portaaliin jo keskeneräisinä
