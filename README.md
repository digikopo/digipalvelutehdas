# OKM toimialan API- ja palvelukehitysstrategia

OKM toimialana tarvitsee jalkautuksen sisältävän API strategian osana arkkitehtuurisuunnittelua. Strategioita on jo monia kuten esimerkiksi älystrategia, mutta niiden vika on että ne jäävät paperitiikereiksi…tai oikeastaan bittitiikereiksi makaamaan palvelimien ja kovalevyjen nurkkiin.

Lähtökohta tulee olla palvelujen rakentaminen osaksi kansallista palveluarkkitehtuuria. Kaikkien toimien tulee edistää tätä tavoitetta ja madaltaa kynnystä innovoida uusia tapoja käyttää digitalisoituvaa tietoa entistä tehokkaammin ja monipuolisemmin.

Teollinen internet, josta paljon puhutaan on nimenä harhaanjohtava. Kyse on teollisesta vallankumouksesta jonka vaikutukset ulottuvat koko yhteiskuntaan ja samat periaatteet tulevat vaikuttamaan jokapäiväiseen elämäämme. Emme siis opetussektorina voi tuudittautua uneen ja olla ottamatta ympärillä tapahtuvaa muutosta huomioon. Teollisen internetin yksi keskeisin elementti on webpohjaiset rajapinnat (API, Application Programmin Interface).

## Rajapintojen kehittäminen avoimella lähdekoodilla

Avoimet rajapinnat ovat hyvä mutta riittämätön lähtökohta API strategialle. Rajapinnat tulee tehdä avointa lähdekoodia käyttäen. Pelkkien avoimien rajapintojen edistäminen ei riitä. Vaikka rajapinnat ovat avoimia ja kaikkien käytössä, myös rajapinnat muuttuvat käyttäjien tarpeiden mukaisesti. Rajapinnan kehittäminen puolestaan vaatii tuntemusta taustajärjestelmästä ja suljetun komponentin kohdalla se tieto on vain tuotteen omistajalla. Tämä puolestaan johtaa siihen tilanteeseen, että suljetun tuotteen omistaja voi mielivaltaisesti päättää mitä muutoksia rajapintaan tehdään jos tehdään ollenkaan. Toiseksi, tämä tilanne estää muutosten kehittämisen vapaan kilpailuttamisen kyseisen komponentin toteuttamien ominaisuuksien osalta. Näin ollen päädytään lähelle perinteistä vendor lock-in tilannetta. Kun kukaan ei tiedä mitä muutosten tekeminen vaatii, voi tuotteen omistaja mielivaltaisesti määritellä kulut tai todeta ettei haluttuja muutoksia voi tehdä.

**Toimenpiteet**
* ....

## Keskitetty kehitysympäristö ja versionhallinta

Kehityksessä tulee käyttää aina kun mahdollista JulkICTLab ympäristöä. Lisäksi OKM:n toimialana tulee keskittää lähdekoodinhallinta Github palveluun tai vaihtoehtoisesti käyttää palveluavastaavaa ratkaisua Gitlab, joka löytyy jo valmiiksi JulkICTLabista. Github palvelun käyttöä puoltaa se fakta, että kehittäjät ovat jo siellä. Github palveluna on avoimen lähdekoodin yhteisön de facto palvelu ja siten kehittäjäpohja laaja. Eriytymällä omaan Gitlab palveluun eristämme itsemme muusta kehittämisyhteisöstä.

**Toimenpiteet**
* ....

## Asiakas ja asiakas

Toinen ohjaava arvo on design lähtöisyys. Palveludesign on jo jonkin aikaa ollut selkeästi nousussa osittain siitä syystä että se nostaa asiakkaan keskiöön. Hyviä ja käytettyjä palveluita ei luoda ilman asiakkaan kuulemista. Asiakas tulee ottaa design prosessiin mukaan niin aikaisin kuin mahdollista. Sama pätee rajapintoihin. Rajapintojen asiakas vain on eri kuin palvelujen asiakas. Palvelujen asiakas on Matti tai Maija Meikäläinen, joka palveluväylän kautta selaimella hoitaa arkensa asioita sinne luotujen palvelujen avulla. Rajapinnan asiakas on kehittäjä, se taho joka puolestaan rakentaa Matille ja Maijalle palvelujen käyttöliittymät ja logiikat palveluväylään.

**Toimenpiteet**
* ....

## Keskitetty rajapintojen hallinta
 
Palveluväylässä on rajapintojen hallinta, mutta kaikki rajapinnat OKM toimialalla eivät käytä palveluväylää. Näin ollen tulee perustaa keskitetty rajapintojen hallintapalvelu. Keskitetty rajapintojen hallinta liittyy tuotteenhallintaan, jonka malli puolestaan on määritelty VTT:n kehittämässä avoimen tuotteen hallintamallissa.

**Toimenpiteet**
* ....

## Avoimen tuotteen hallintamalli

VTT-Technical-Research-Centre-of-FinlandKehittämisen konseptina tulee hyödyntää Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa. Avoimen tuotteen hallintamalli määrittelee säännöt, joilla voidaan perustaa julkisen hallinnon organisaatioille käyttäjäyhteisö avoimen lähdekoodin ohjelmistotuotteen kehittämistä, ohjausta ja hallintaa varten. Malli selkeyttää mm. tuotteen omistajuutta, osapuolten vastuita sekä palvelun ylläpidon ja kehittämisen ohjausta. VTT:n luomaa mallia pyritään soveltamaan kaikissa JulkICT:n projekteissa, joissa tuotetaan palveluja avoimella lähdekoodilla. Kuten aiemmin on todettu asiakkuuksia on ainakin kahden tyyppisiä, joista rajapinnan asiakas on kehittäjä. Rajapinta tulee siis nähdä palveluna siinä missä Matti ja Maija Meikäläisen käyttämät palveluväylän näkymät. Rajapinta on tuote ja sen kehittämiseen tulee käyttää myös Avoimen tuotteen hallintamallin mukaista tuotteenhallintasuunnitelmaa.

Avoimen tuotteen hallintamallia tulee kehittää edelleen yhteistyössä VTT:n ja muiden tahojen kanssa. Mallia tulee kehittää siten, että se ottaa huomioon rajapintojen kehittämisen erityispiirteet. Alla oleva malli on yksi tapa nähdä rajapintojen kehittämisen malli.
![alt text](https://raw.githubusercontent.com/digiokm/palvelukehitys/master/images/apiops.png)

**Toimenpiteet**
* ....

## Iteratiivista ketterää kehitystä

**Avainsanat**
* osallistava
* avoin
* ketterä
* kokeilukulttuuri

Massiiviset yli vuoden mittaiset rajapintojen kehitysprojektit tulee kieltää. Sen sijaan tulee kehittää kokeilukulttuuria ja tarvittaessa sisällyttää Avoimen tuotteen hallintamalliin. Digitalisaatiosta saadaan paras hyöty, kun yhteiskunnan kaikki prosessit suunnitellaan kokonaan uudella digitaalisuuteen sopivalla tavalla. Lisäksi tarvitaan kokeiluja eikä loppuun saakka hiottuja täydellisiä suunnitelmia. Toteutus tulee olla MVP tyyppiseen minimaalisen toteutukseen perustuvaa, jolloin tehdään vain välttämättömin osuus. Syntynyt tuotos testataan välittömästi loppukäyttäjillä ja saadun palautteen mukaan jatketaan kehitystä. Toisin sanoen kehitys tulee tapahtua avoimesti alussa raakileita ja keskeneräistä (mutta toimivaa) tuotosta hyväksikäyttäen.

**Toimenpiteet**
* ....


## Palvelukehityksen portaali

Keskitetty rajapintojen hallintapalvelusta on osa laajempaa kokonaisuutta, josta löytyy myös ajantasaiset rajapintojen dokumentaatiot, valmiit koodiesimerkit rajapintojen hyödyntämiseen, valmiit ohjelmistokomponenttikirjastot eri käyttöjärjestelmille (SDK), hiekkalaatikko API:en kokeilemiseen ja mahdollisuus vuorovaikutukseen kehittäjäyhteisön kanssa. Tässä kohdin tulee hyödyntää FORGE alustaa ja yhteisöä.

Portaali tarjoaa rajapintojen asiakkaille eli palvelukehittäjille yhden pisteen, josta tieto ja rajapinnat löytyvät. Tämä puolestaan selkeyttää ja nopeuttaa palvelukehitystä, joka kuten aiemmin on todettu tulee entistä enemmän pohjautumaan webpohjaisten rajapintojen hyödyntämiseen.

**Toimenpiteet**
* ....
