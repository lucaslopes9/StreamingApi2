<?php
error_reporting(0);
function my_encrypt($data, $key='XXYM0LTtOwwDO7wZ0VVz') {

	$encryption_key = base64_decode($key);
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $encryption_key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

function make_bitly_url($url, $bitly_login, $bitly_api,  $format = 'xml', $version = '2.0.1')
{
  //create the URL
  $bitly = 'http://api.bit.ly/shorten?version='.$version.'&longUrl='.urlencode($url).'&login='.$bitly_login.'&apiKey='.$bitly_api.'&format='.$format;
  $xml = simplexml_load_file($bitly) -> results;
  foreach($xml -> nodeKeyVal as $nodeKeyVal) {
    return (string)$nodeKeyVal -> shortUrl;
  }
}

function RedesSociais(){
	include("conexao.php");
	$Retornar = "";
	
	$CadUser = InfoUser(4);
	
	$SQL = "SELECT * FROM rede_social WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	$facebook = $Ln['facebook'];
	$whatsapp = $Ln['whatsapp'];
	$telegram = $Ln['telegram'];
	
	if(!empty($facebook)){
		$Retornar .= "<li class=\"xn-icon-button pull-right\">
        	<a target=\"_blank\" title=\"Facebook\" href=\"".$facebook."\"><span class=\"fa fa-facebook\"></span></a>
        </li>";
	}
	
	if(!empty($whatsapp)){
		$Retornar .= "<li class=\"xn-icon-button pull-right\">
        	<a target=\"_blank\" title=\"WhatsApp\" href=\"https://api.whatsapp.com/send?phone=".$whatsapp."&text=\"><span class=\"fa fa-whatsapp\"></span></a>
        </li>";
	}
	
	if(!empty($telegram)){
		$Retornar .= "<li class=\"xn-icon-button pull-right\">
        	<a target=\"_blank\" title=\"Telegram\" href=\"".$telegram."\"><span class=\"fa fa-telegram\"></span></a>
        </li>";
	}
	
	return $Retornar;
	
}

function GerarCupom(){
		$salt = "abchefghjkmnpqrstuvwxyz0123456789";
		srand((double)microtime()*1000000);
		for($i = 0; $i <= 3; $i++){
		$num = rand() % 33;
		$tmp = substr($salt, $num, 1);
		$pass = $pass . $tmp;
		
		$num2 = rand() % 33;
		$tmp2 = substr($salt, $num2, 1);
		$pass2 = $pass2 . $tmp2;
		
		$num3 = rand() % 33;
		$tmp3 = substr($salt, $num3, 1);
		$pass3 = $pass3 . $tmp3;
		
		$num4 = rand() % 33;
		$tmp4 = substr($salt, $num4, 1);
		$pass4 = $pass4 . $tmp4;
		
		$num5 = rand() % 33;
		$tmp5 = substr($salt, $num5, 1);
		$pass5 = $pass5 . $tmp5;
		}
		return $pass."-".$pass2."-".$pass3."-".$pass4."-".$pass5;
}

function IdiomaRetorno($op){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	if( ($idioma == "br") && ($op == 1)){
		return "../idioma/br.php";
	}
	elseif( ($idioma == "en") && ($op == 1)){
		return "../idioma/en.php";
	}
	elseif( ($idioma == "es") && ($op == 1)){
		return "../idioma/es.php";
	}
	elseif( ($idioma == "it") && ($op == 1)){
		return "../idioma/it.php";
	}
	elseif( ($idioma == "ge") && ($op == 1)){
		return "../idioma/ge.php";
	}
	elseif( ($idioma == "fr") && ($op == 1)){
		return "../idioma/fr.php";
	}
	elseif($op == 2){
		return "-".$idioma;
	}
}

function Idioma($op){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	if( ($idioma == "br") && ($op == 1)){
		return "idioma/br.php";
	}
	elseif( ($idioma == "en") && ($op == 1)){
		return "idioma/en.php";
	}
	elseif( ($idioma == "es") && ($op == 1)){
		return "idioma/es.php";
	}
	elseif( ($idioma == "it") && ($op == 1)){
		return "idioma/it.php";
	}
	elseif( ($idioma == "ge") && ($op == 1)){
		return "idioma/ge.php";
	}
	elseif( ($idioma == "fr") && ($op == 1)){
		return "idioma/fr.php";
	}
	elseif($op == 2){
		return "-".$idioma;
	}
}

function IdiomaMenu(){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	
	if($idioma == "br"){
		$menu = "<li><a href=\"index.php?lang=en\"><span class=\"flag flag-en\"></span> Inglês</a></li>
		<li><a href=\"index.php?lang=es\"><span class=\"flag flag-es\"></span> Espanhol</a></li>
		<li><a href=\"index.php?lang=it\"><span class=\"flag flag-it\"></span> Italiano</a></li>
		<li><a href=\"index.php?lang=ge\"><span class=\"flag flag-ge\"></span> Alemão</a></li>
		<li><a href=\"index.php?lang=fr\"><span class=\"flag flag-fr\"></span> Francês</a></li>";
	}
	elseif($idioma == "en"){
		$menu = "<li><a href=\"index.php?lang=br\"><span class=\"flag flag-br\"></span> Portuguese</a></li>
		<li><a href=\"index.php?lang=es\"><span class=\"flag flag-es\"></span> Spanish</a></li>
		<li><a href=\"index.php?lang=it\"><span class=\"flag flag-it\"></span> 
Italian</a></li>
		<li><a href=\"index.php?lang=ge\"><span class=\"flag flag-ge\"></span> German</a></li>
		<li><a href=\"index.php?lang=fr\"><span class=\"flag flag-fr\"></span> French</a></li>";
	}
	elseif($idioma == "es"){
		$menu = "<li><a href=\"index.php?lang=br\"><span class=\"flag flag-br\"></span> Portugués</a></li>
		<li><a href=\"index.php?lang=en\"><span class=\"flag flag-en\"></span> Inglés</a></li>
		<li><a href=\"index.php?lang=it\"><span class=\"flag flag-it\"></span> Italiano</a></li>
		<li><a href=\"index.php?lang=ge\"><span class=\"flag flag-ge\"></span> Alemán</a></li>
		<li><a href=\"index.php?lang=fr\"><span class=\"flag flag-fr\"></span> Francés</a></li>";
	}
	elseif($idioma == "it"){
		$menu = "<li><a href=\"index.php?lang=br\"><span class=\"flag flag-br\"></span> Portoghese</a></li>
		<li><a href=\"index.php?lang=en\"><span class=\"flag flag-en\"></span> Inglese</a></li>
		<li><a href=\"index.php?lang=es\"><span class=\"flag flag-es\"></span> Spagnolo</a></li>
		<li><a href=\"index.php?lang=ge\"><span class=\"flag flag-ge\"></span> Tedesco</a></li>
		<li><a href=\"index.php?lang=fr\"><span class=\"flag flag-fr\"></span> Francese</a></li>";
	}
	elseif($idioma == "ge"){
		$menu = "<li><a href=\"index.php?lang=br\"><span class=\"flag flag-br\"></span> Portugiesisch</a></li>
		<li><a href=\"index.php?lang=en\"><span class=\"flag flag-en\"></span> Englisch</a></li>
		<li><a href=\"index.php?lang=es\"><span class=\"flag flag-es\"></span> Spanisch</a></li>
		<li><a href=\"index.php?lang=it\"><span class=\"flag flag-it\"></span> Italienisch</a></li>
		<li><a href=\"index.php?lang=fr\"><span class=\"flag flag-fr\"></span> Französisch</a></li>";
	}
	elseif($idioma == "fr"){
		$menu = "<li><a href=\"index.php?lang=br\"><span class=\"flag flag-br\"></span> Portugais</a></li>
		<li><a href=\"index.php?lang=en\"><span class=\"flag flag-en\"></span> Anglais</a></li>
		<li><a href=\"index.php?lang=es\"><span class=\"flag flag-es\"></span> Espagnol</a></li>
		<li><a href=\"index.php?lang=it\"><span class=\"flag flag-it\"></span> Italien</a></li>
		<li><a href=\"index.php?lang=ge\"><span class=\"flag flag-ge\"></span> Allemand</a></li>";
	}
	
	return $menu;
}

function convertmb($filesize)
	{
		if (!is_numeric($filesize)) return $filesize;
		$soam = false;
		if ($filesize < 0) {
			$filesize = abs($filesize);
			$soam = true;
		}
		if ($filesize >= 1024 * 1024 * 1024 * 1024) $value = ($soam ? "-" : "") . round($filesize / (1024 * 1024 * 1024 * 1024) , 2) . " TB";
		elseif ($filesize >= 1024 * 1024 * 1024) $value = ($soam ? "-" : "") . round($filesize / (1024 * 1024 * 1024) , 2) . " GB";
		elseif ($filesize >= 1024 * 1024) $value = ($soam ? "-" : "") . round($filesize / (1024 * 1024) , 2) . " MB";
		elseif ($filesize >= 1024) $value = ($soam ? "-" : "") . round($filesize / (1024) , 2) . " KB";
		else $value = ($soam ? "-" : "") . $filesize . " Bytes";
		return $value;
	}

function SalvarIdioma($idioma){
	//Salva o cookie do Idioma em segundos
	$url = empty($_SERVER['HTTP_REFERER']) ? "index.php" : $_SERVER['HTTP_REFERER'];
	setcookie("idioma", $idioma, time()+31622400, "/");
	header("Location: ".$url."");
}

function VerificarInfoOnline(){
	include("conexao.php");
	
	if( !isset($_SESSION['nome']) || !isset($_SESSION['sobrenome'])  || !isset($_SESSION['email']) || !isset($_SESSION['foto']) || !isset($_SESSION['celular']) || !isset($_SESSION['data_nascimento']) || !isset($_SESSION['data_cadastro']) || !isset($_SESSION['CadUser']) ){
		$id_user = InfoUser(1);
		$usuario = InfoUser(2);
		$SQLUser = "SELECT CadUser, nome, sobrenome, email, foto, celular, data_nascimento, data_cadastro FROM ".SelectTabela()." WHERE id = :id AND usuario = :usuario";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':id', $id_user, PDO::PARAM_INT);
		$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		
		$CadUser = empty($LnUser['CadUser']) ? "" : $LnUser['CadUser'];
		$Nome = empty($LnUser['nome']) ? "" : $LnUser['nome'];
		$Sobrenome = empty($LnUser['sobrenome']) ? "" : $LnUser['sobrenome'];
		$email = empty($LnUser['email']) ? "" : $LnUser['email'];
		$foto = empty($LnUser['foto']) ? "" : $LnUser['foto'];
		$celular = empty($LnUser['celular']) ? "" : $LnUser['celular'];
		$data_nascimento = empty($LnUser['data_nascimento']) ? "" : $LnUser['data_nascimento'];
		$data_cadastro = empty($LnUser['data_cadastro']) ? "" : $LnUser['data_cadastro'];
		
		$_SESSION['CadUser'] = $CadUser;
		$_SESSION['nome'] = $Nome;
		$_SESSION['sobrenome'] = $Sobrenome;
		$_SESSION['email'] = $email;
		$_SESSION['foto'] = $foto;
		$_SESSION['celular'] = $celular;
		$_SESSION['data_nascimento'] = $data_nascimento;
		$_SESSION['data_cadastro'] = $data_cadastro;
		
		return array($Nome, $Sobrenome, $email, $foto, $celular, $data_nascimento, $data_cadastro, $CadUser);
	}
	else{
		return array($_SESSION['nome'], $_SESSION['sobrenome'], $_SESSION['email'], $_SESSION['foto'], $_SESSION['celular'], $_SESSION['data_nascimento'], $_SESSION['data_cadastro'], $_SESSION['CadUser']);
	}
	
	
	
}

function ValidarUsuario($usuario, $senha){
	include("conexao.php"); 
        $timestamp = time();    
        
	//Teste
	$SQLTeste = "SELECT `id`, `CadUser`, `usuario`, `senha`, `nome`, `sobrenome`, `email`, `foto`, `celular`, `data_nascimento`, `data_cadastro`, `data_premio`, `obs`, `MensagemInterna` FROM `teste` WHERE `usuario` = :usuario AND `senha` = :senha LIMIT 1";
	$SQLTeste = $painel_user->prepare($SQLTeste);
	$SQLTeste->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLTeste->bindParam(':senha', $senha, PDO::PARAM_STR);
	$SQLTeste->execute();
  	$LnTeste = $SQLTeste->fetch();
	
	if(!empty($LnTeste)) {
		$_SESSION['id'] = $LnTeste['id'];
		$_SESSION['CadUser'] = $LnTeste['CadUser'];
		$_SESSION['usuario'] = $LnTeste['usuario'];
		$_SESSION['acesso'] = 4;
		$_SESSION['nome'] = $LnTeste['nome'];
		$_SESSION['sobrenome'] = $LnTeste['sobrenome'];
		$_SESSION['email'] = $LnTeste['email'];
		$_SESSION['foto'] = $LnTeste['foto'];
		$_SESSION['celular'] = $LnTeste['celular'];
		$_SESSION['data_nascimento'] = $LnTeste['data_nascimento'];
		$_SESSION['data_cadastro'] = $LnTeste['data_cadastro'];
		$_SESSION['data_premio'] = $LnTeste['data_premio'];
		$_SESSION['obs'] = trim($LnTeste['obs']);
		$_SESSION['MensagemInterna'] = $LnTeste['MensagemInterna'];
		$getBrowser=getBrowser();
		InserirAcesso($LnTeste['usuario'], 1, $_SERVER['REMOTE_ADDR'], $getBrowser['name'], $getBrowser['version'], $getBrowser['platform']);
		return true;
	}
	
	//Usuário
	$SQLUser = "SELECT `id`, `CadUser`, `usuario`, `senha`, `nome`, `sobrenome`, `email`, `foto`, `celular`, `data_nascimento`, `data_cadastro`, `data_premio`, `ValorCobrado`, `ValorCobradoCab`, `obs`, `MensagemInterna` FROM `usuario` WHERE `usuario` = :usuario AND `senha` = :senha LIMIT 1";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->bindParam(':senha', $senha, PDO::PARAM_STR);
	$SQLUser->execute();
  	$LnUser = $SQLUser->fetch();
	
	if(!empty($LnUser)) {
		$_SESSION['id'] = $LnUser['id'];
		$_SESSION['CadUser'] = $LnUser['CadUser'];
		$_SESSION['usuario'] = $LnUser['usuario'];
		$_SESSION['acesso'] = 3;
		$_SESSION['nome'] = $LnUser['nome'];
		$_SESSION['sobrenome'] = $LnUser['sobrenome'];
		$_SESSION['email'] = $LnUser['email'];
		$_SESSION['foto'] = $LnUser['foto'];
		$_SESSION['celular'] = $LnUser['celular'];
		$_SESSION['data_nascimento'] = $LnUser['data_nascimento'];
		$_SESSION['data_cadastro'] = $LnUser['data_cadastro'];
		$_SESSION['data_premio'] = $LnUser['data_premio'];
		$_SESSION['ValorCobrado'] = $LnUser['ValorCobrado'];
		$_SESSION['ValorCobradoCab'] = $LnUser['ValorCobradoCab'];
		$_SESSION['obs'] = trim($LnUser['obs']);
		$_SESSION['MensagemInterna'] = $LnUser['MensagemInterna'];
		$getBrowser=getBrowser();
		InserirAcesso($LnUser['usuario'], 1, $_SERVER['REMOTE_ADDR'], $getBrowser['name'], $getBrowser['version'], $getBrowser['platform']);
		return true;
	}
	
	//Revendedor
	$SQLRev = "SELECT `id`, `CadUser`, `usuario`, `senha`, `nome`, `sobrenome`, `email`, `foto`, `celular`, `data_nascimento`, `data_cadastro`, `data_premio`, `PrePago`, `Cota`, `CotaDias`, `obs`, `MensagemInterna` FROM `rev` WHERE `usuario` = :usuario AND `senha` = :senha LIMIT 1";
	$SQLRev = $painel_user->prepare($SQLRev);
	$SQLRev->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLRev->bindParam(':senha', $senha, PDO::PARAM_STR);
	$SQLRev->execute();
  	$LnRev = $SQLRev->fetch();
	
	if(!empty($LnRev)) {
		$_SESSION['id'] = $LnRev['id'];
		$_SESSION['CadUser'] = $LnRev['CadUser'];
		$_SESSION['usuario'] = $LnRev['usuario'];
		$_SESSION['acesso'] = 2;
		$_SESSION['nome'] = $LnRev['nome'];
		$_SESSION['sobrenome'] = $LnRev['sobrenome'];
		$_SESSION['email'] = $LnRev['email'];
		$_SESSION['foto'] = $LnRev['foto'];
		$_SESSION['celular'] = $LnRev['celular'];
		$_SESSION['data_nascimento'] = $LnRev['data_nascimento'];
		$_SESSION['data_cadastro'] = $LnRev['data_cadastro'];
		$_SESSION['data_premio'] = $LnRev['data_premio'];
		$_SESSION['PrePago'] = $LnRev['PrePago'];
		$_SESSION['Cota'] = $LnRev['Cota'];
		$_SESSION['CotaDias'] = $LnRev['CotaDias'];
		$_SESSION['obs'] = trim($LnRev['obs']);
		$_SESSION['MensagemInterna'] = $LnRev['MensagemInterna'];
		$getBrowser=getBrowser();
		InserirAcesso($LnRev['usuario'], 1, $_SERVER['REMOTE_ADDR'], $getBrowser['name'], $getBrowser['version'], $getBrowser['platform']);
		return true;
         }
	
	//Administrador
	$SQLAdn = "SELECT `id`, `CadUser`, `usuario`, `senha`, `nome`, `sobrenome`, `email`, `foto`, `celular`, `data_nascimento`, `data_cadastro`, `obs`, `MensagemInterna` FROM `admin` WHERE `usuario` = :usuario AND `senha` = :senha LIMIT 1";
	$SQLAdn = $painel_user->prepare($SQLAdn);
	$SQLAdn->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLAdn->bindParam(':senha', $senha, PDO::PARAM_STR);
	$SQLAdn->execute();
  	$LnAdm = $SQLAdn->fetch();
	
	if(!empty($LnAdm)) {
		$_SESSION['id'] = $LnAdm['id'];
		$_SESSION['CadUser'] = $LnAdm['CadUser'];
		$_SESSION['usuario'] = $LnAdm['usuario'];
		$_SESSION['acesso'] = 1;
		$_SESSION['nome'] = $LnAdm['nome'];
		$_SESSION['sobrenome'] = $LnAdm['sobrenome'];
		$_SESSION['email'] = $LnAdm['email'];
		$_SESSION['foto'] = $LnAdm['foto'];
		$_SESSION['celular'] = $LnAdm['celular'];
		$_SESSION['data_nascimento'] = $LnAdm['data_nascimento'];
		$_SESSION['data_cadastro'] = $LnAdm['data_cadastro'];
		$_SESSION['PrePago'] = "N";
		$_SESSION['obs'] = trim($LnAdm['obs']);
		$_SESSION['MensagemInterna'] = $LnAdm['MensagemInterna'];
		$getBrowser=getBrowser();
		InserirAcesso($LnAdm['usuario'], 1, $_SERVER['REMOTE_ADDR'], $getBrowser['name'], $getBrowser['version'], $getBrowser['platform']);
		return true;
	}
		return false;
}

function ProtegePag($AtuSenha = NULL){
  include("conexao.php");
  
 
 if(empty($_SESSION['id']) || empty($_SESSION['usuario']) || empty($_SESSION['acesso']) ) {
    ExpulsaVisitante();
  } 
  elseif(!empty($_SESSION['id']) && !empty($_SESSION['usuario']) && !empty($_SESSION['acesso']) ) {
	
	if($_SESSION['acesso'] == 1){
		$REQUEST_URI = $_SERVER['REQUEST_URI'];
		if( (substr_count($REQUEST_URI, "lock-pin.php") == 0) && (substr_count($REQUEST_URI, "validar-pin.php") == 0) ){
			$CookiePin = empty($_COOKIE['CookiePin']) ? "" : $_COOKIE['CookiePin'];
			
			if(!empty($CookiePin)){
				$CookiePin = my_decrypt($CookiePin);
			}
			
				if(!empty($CookiePin)){
					if( md5(md5(md5(md5(md5($CookiePin))))) == "13d63bd44e84e973ea07c7e6dfaa19bb"){	
						return true;
					}
					else{
						unset($_COOKIE['CookiePin']);
						setcookie('CookiePin', '', time() - 3600, '/');
						return header("Location: lock-pin.php");
					}
				}
				else{
					return header("Location: lock-pin.php");
				}
		}
		
		return true;
		
	}
	else{ 
		return true;
	}
	
  }
  	return false;
}

function Sair(){
  include("conexao.php");
  
  $getBrowser=getBrowser();
  InserirAcesso($_SESSION['usuario'], 2, $_SERVER['REMOTE_ADDR'], $getBrowser['name'], $getBrowser['version'], $getBrowser['platform']);
  
  unset($_SESSION['id'], $_SESSION['usuario'], $_SESSION['acesso']);
  session_destroy();
  header("Location: login.php");
}

function ExpulsaVisitante(){
  include("conexao.php");
  unset($_SESSION['id'], $_SESSION['usuario'], $_SESSION['acesso']);
  session_destroy();
  header("Location: login.php");
}


function MensagemAlerta($titulo, $texto, $tipo, $url = NULL){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	if($tipo == "success"){
		$class = "fa-check";
	}
	elseif($tipo == "warning"){
		$class = "fa-warning";
	}
	elseif($tipo == "info"){
		$class = "fa-info";
	}
	elseif($tipo == "danger"){
		$class = "fa-times";
	}
	else{
		$class = "fa-info";
	}
	
	if(empty($url)){
	$red = "$(this).parents('#MensagemBox').removeClass('open'); $(\"LimparScript\").remove(); return false;";
	}
	else{
	$red = "var url = '".$url."'; $.post('RedirecionarScript.php', {url: url}, function(resposta) { $(\"#StatusGeral\").html(''); $(\"#StatusGeral\").html(resposta); });";
	}
	
	$msg = "<LimparScript><script>$('.mb-control-close').on('click',function(){ ".$red." }); $('#MensagemBox').toggleClass('open');</script><div class=\"message-box message-box-".$tipo." animated fadeIn\" id=\"MensagemBox\"><div class=\"mb-container\"><div class=\"mb-middle\"><div class=\"mb-title\"><span class=\"fa ".$class."\"></span> ".$titulo."</div><div class=\"mb-content\"><p>".$texto."</p></div><div class=\"mb-footer\"><button class=\"btn btn-default btn-lg pull-right mb-control-close\">".$_TRA['fechar']."</button></div></div></div></div></LimparScript>";	
	return $msg;	
}

function MensagemConfirmar($titulo, $texto, $tipo, $link, $fa, $bt1, $bt2){
	
	$msg = "<script>$('.mb-control-close').on('click',function(){ $(this).parents('#MensagemBox').removeClass('open'); return false; }); $('#MensagemBox').toggleClass('open');</script><div class=\"message-box animated fadeIn\" id=\"MensagemBox\"><div class=\"mb-container\"><div class=\"mb-middle\"><div class=\"mb-title\"><span class=\"fa ".$fa."\"></span> ".$titulo."</div><div class=\"mb-content\"><p>".$texto."</p></div><div class=\"mb-footer\"><div class=\"pull-right\"><a href=\"".$link."\" class=\"btn btn-".$tipo." btn-lg\">".$bt1."</a>&nbsp;<button class=\"btn btn-default btn-lg mb-control-close\">".$bt2."</button></div></div></div></div></div>";
	return $msg;	
}

function MensagemConfirmarJS($id, $titulo, $texto, $tipo, $link, $fa, $bt1, $bt2){
	include_once(Idioma(1));
	global $_TRA;

	$msg = "<script>$(function(){ $(\"a.MensagemJS\").click(function() { var id = '".$id."'; $(\".mb-content\").html(''); $(\".mb-content\").html('<p><center>".$_TRA['aeapd']."<br><img src=\"img/owl/AjaxLoader.gif\"></p></center>'); $.post('".$link.".php', {id: id}, function(resposta) { $(\"#MensagemBox\").removeClass('open'); $(\"#StatusGeral\").html(''); $(\"#StatusGeral\").html(resposta); }); }); }); $('.mb-control-close').on('click',function(){ $(this).parents('#MensagemBox').removeClass('open'); return false; }); $('#MensagemBox').toggleClass('open');</script><div class=\"message-box animated fadeIn\" id=\"MensagemBox\"><div class=\"mb-container\"><div class=\"mb-middle\"><div class=\"mb-title\"><span class=\"fa ".$fa."\"></span> ".$titulo."</div><div class=\"mb-content\"><p>".$texto."</p></div><div class=\"mb-footer\"><div class=\"pull-right\"><a class=\"MensagemJS btn btn-".$tipo." btn-lg\">".$bt1."</a>&nbsp;<button class=\"btn btn-default btn-lg mb-control-close\">".$bt2."</button></div></div></div></div></div>";
	return $msg;
}

function MensagemConfirmarStatus($id, $perfil, $titulo, $texto, $tipo, $link, $fa, $bt1, $bt2){
	include_once(Idioma(1));
	global $_TRA;

	$msg = "<script>$(function(){ $(\"a.MensagemJS\").click(function() { var id = '".$id."'; var perfil = '".$perfil."'; $(\".mb-content\").html(''); $(\".mb-content\").html('<p><center>".$_TRA['aeapd']."<br><img src=\"img/owl/AjaxLoader.gif\"></p></center>'); $.post('".$link.".php', {id: id, perfil: perfil}, function(resposta) { $(\"#MensagemBox\").removeClass('open'); $(\"#StatusGeral\").html(''); $(\"#StatusGeral\").html(resposta); }); }); }); $('.mb-control-close').on('click',function(){ $(this).parents('#MensagemBox').removeClass('open'); return false; }); $('#MensagemBox').toggleClass('open');</script><div class=\"message-box animated fadeIn\" id=\"MensagemBox\"><div class=\"mb-container\"><div class=\"mb-middle\"><div class=\"mb-title\"><span class=\"fa ".$fa."\"></span> ".$titulo."</div><div class=\"mb-content\"><p>".$texto."</p></div><div class=\"mb-footer\"><div class=\"pull-right\"><a class=\"MensagemJS btn btn-".$tipo." btn-lg\">".$bt1."</a>&nbsp;<button class=\"btn btn-default btn-lg mb-control-close\">".$bt2."</button></div></div></div></div></div>";
	return $msg;
}

function MensagemConfirmarJS2($camposMarcados, $status, $titulo, $texto, $tipo, $link, $fa, $bt1, $bt2){
	include_once(Idioma(1));
	global $_TRA;
	
	$string_array = implode("|", $camposMarcados);

	$msg = "<script>$(function(){ $(\"a.MensagemJS\").click(function() { var i, camposMarcados, string_array; string_array = '".$string_array."'; camposMarcados = string_array.split('|'); var status = '".$status."'; $(\".mb-content\").html(''); $(\".mb-content\").html('<p><center>".$_TRA['aeapd']."<br><img src=\"img/owl/AjaxLoader.gif\"></p></center>'); $.post('".$link.".php', {camposMarcados: camposMarcados, status: status}, function(resposta) { $(\"#MensagemBox\").removeClass('open'); $(\"#StatusGeral\").html(''); $(\"#StatusGeral\").html(resposta); }); }); }); $('.mb-control-close').on('click',function(){ $(this).parents('#MensagemBox').removeClass('open'); return false; }); $('#MensagemBox').toggleClass('open');</script><div class=\"message-box animated fadeIn\" id=\"MensagemBox\"><div class=\"mb-container\"><div class=\"mb-middle\"><div class=\"mb-title\"><span class=\"fa ".$fa."\"></span> ".$titulo."</div><div class=\"mb-content\"><p>".$texto."</p></div><div class=\"mb-footer\"><div class=\"pull-right\"><a class=\"MensagemJS btn btn-".$tipo." btn-lg\">".$bt1."</a>&nbsp;<button class=\"btn btn-default btn-lg mb-control-close\">".$bt2."</button></div></div></div></div></div>";
	return $msg;
}

function Redirecionar($url){
	return "<script language= \"JavaScript\">
			location.href=\"".$url."\"
			</script>";
}

function Foto($foto){
	if(empty($foto)){
		$f = "img/foto/no-image.jpg";
	}
	else{
		$f = "img/foto/".$foto;
		if(file_exists($f)){
			return $f;
		}
		else{
			return "img/foto/no-image.jpg";
		}
		
	}
	return $f;
}

function FotoPerfil($foto){
	if(empty($foto)){
		$f = "img/perfil/sem-perfil.ico";
	}
	else{
		$f = "img/perfil/".$foto;
		if(file_exists($f)){
			return $f;
		}
		else{
			return "img/perfil/sem-perfil.ico";
		}
		
	}
	return $f;
}

function SelectTabela(){
	include("conexao.php");
	
	if($_SESSION['acesso'] == 1){
		$tabela = "admin";
	}
	elseif($_SESSION['acesso'] == 2){
		$tabela = "rev";
	}
	elseif($_SESSION['acesso'] == 3){
		$tabela = "usuario";
	}
	elseif($_SESSION['acesso'] == 4){
		$tabela = "teste";
	}
	return $tabela;
}

function InfoUser($id){
	include("conexao.php");
	
	if($id == 1){
		return $_SESSION['id'];
	}
	elseif($id == 2){
		return $_SESSION['usuario'];
	}
	elseif($id == 3){
		return $_SESSION['acesso'];
	}	
	elseif($id == 4){
		return $_SESSION['CadUser'];
	}
	else{
		return $_SESSION['id'];	
	}
}

function NivelAcesso(){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	if(InfoUser(3) == 1){
		$n = $_TRA['admin'];
	}
	elseif(InfoUser(3) == 2){
		$n = $_TRA['rev'];
	}
	elseif(InfoUser(3) == 3){
		$n = $_TRA['user'];
	}
	elseif(InfoUser(3) == 4){
		$n = $_TRA['teste'];
	}
	return $n;	
}

function SenhaAtual(){
	include("conexao.php");
	
	$id = InfoUser(1);
	$usuario = InfoUser(2);
	$SQLUser = "SELECT `senha` FROM `".SelectTabela()."` WHERE `id` = :id AND `usuario` = :usuario LIMIT 1";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':id', $id, PDO::PARAM_INT);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->execute();
  	$LnUser = $SQLUser->fetch();
	
	if(empty($LnUser)){
		return false;
	}
	else{
		return $LnUser['senha'];
	}
}

function ConverterData($data, $op){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	if( ($idioma == "br") || ($idioma == "fr") || ($idioma == "it") || ($idioma == "es") ){
		if($op == 1){
			return date('d/m/Y', strtotime($data));
		}
		elseif($op == 2){
			$ex = explode("/",$data);
			return $ex[2]."-".$ex[1]."-".$ex[0];
		}
		elseif($op == 3){
			return date('H:i d.m.Y', strtotime($data));
		}
	}elseif( ($idioma == "ge") || ($idioma == "en") ){
		if($op == 1){
			return date('Y/m/d', strtotime($data));
		}
		elseif($op == 2){
			return str_replace("/","-",$data);
		}
		elseif($op == 3){
			return date('H:i d.m.Y', strtotime($data));
		}
	}
}

function ConverterDataTime($data){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	if( ($idioma == "br") || ($idioma == "fr") || ($idioma == "it") || ($idioma == "es") ){
			return date('d/m/Y', $data);
	}
	elseif( ($idioma == "ge") || ($idioma == "en") ){
			return date('Y/m/d', $data);
	}
	else{
		return date('d/m/Y', $data);
	}
}

function LimparCelular($celular){
	$celular = str_replace("(","",$celular);
	$celular = str_replace(")","",$celular);
	$celular = str_replace("-","",$celular);
	$celular = str_replace(" ","",$celular);
	
	return trim($celular);
}

function getBrowser() 
{ 
    $u_agent = $_SERVER['HTTP_USER_AGENT']; 
    $bname = 'Unknown';
    $platform = 'Unknown';
    $version= "";

    //First get the platform?
    if (preg_match('/linux/i', $u_agent)) {
        $platform = 'linux';
    }
    elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
        $platform = 'mac';
    }
    elseif (preg_match('/windows|win32/i', $u_agent)) {
        $platform = 'windows';
    }
    
    // Next get the name of the useragent yes seperately and for good reason
    if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent)) 
    { 
        $bname = 'Internet Explorer'; 
        $ub = "MSIE"; 
    } 
    elseif(preg_match('/Firefox/i',$u_agent)) 
    { 
        $bname = 'Mozilla Firefox'; 
        $ub = "Firefox"; 
    } 
    elseif(preg_match('/Chrome/i',$u_agent)) 
    { 
        $bname = 'Google Chrome'; 
        $ub = "Chrome"; 
    } 
    elseif(preg_match('/Safari/i',$u_agent)) 
    { 
        $bname = 'Apple Safari'; 
        $ub = "Safari"; 
    } 
    elseif(preg_match('/Opera/i',$u_agent)) 
    { 
        $bname = 'Opera'; 
        $ub = "Opera"; 
    } 
    elseif(preg_match('/Netscape/i',$u_agent)) 
    { 
        $bname = 'Netscape'; 
        $ub = "Netscape"; 
    } 
    
    // finally get the correct version number
    $known = array('Version', $ub, 'other');
    $pattern = '#(?<browser>' . join('|', $known) .
    ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
    if (!preg_match_all($pattern, $u_agent, $matches)) {
        // we have no matching number just continue
    }
    
    // see how many we have
    $i = count($matches['browser']);
    if ($i != 1) {
        //we will have two since we are not using 'other' argument yet
        //see if version is before or after the name
        if (strripos($u_agent,"Version") < strripos($u_agent,$ub)){
            $version= $matches['version'][0];
        }
        else {
            $version= $matches['version'][1];
        }
    }
    else {
        $version= $matches['version'][0];
    }
    
    // check if we have a number
    if ($version==null || $version=="") {$version="?";}
    
    return array(
        'userAgent' => $u_agent,
        'name'      => $bname,
        'version'   => $version,
        'platform'  => $platform,
        'pattern'    => $pattern
    );
} 

function VersaoPainel(){
	include("conexao.php");
	
	if(isset($_SESSION['VersaoPainel'])){
		return $_SESSION['VersaoPainel'];
	}
	else{
	
	$SQL = "SELECT versao FROM versao";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	$_SESSION['VersaoPainel'] = $Ln['versao'];
	
	return $Ln['versao'];
	}
}

function InserirAcesso($user, $status, $ip, $navegador, $versao, $plataforma){
	include("conexao.php");
	$SQL = "INSERT INTO registro_acesso (
			CadUser,
            status,
            ip,
			navegador,
			versao,
			plataforma
            ) VALUES (
            :CadUser, 
            :status, 
            :ip, 
			:navegador, 
			:versao, 
			:plataforma
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $user, PDO::PARAM_STR);
	$SQL->bindParam(':status', $status, PDO::PARAM_INT);
	$SQL->bindParam(':ip', $ip, PDO::PARAM_STR);
	$SQL->bindParam(':navegador', $navegador, PDO::PARAM_STR);
	$SQL->bindParam(':versao', $versao, PDO::PARAM_STR);
	$SQL->bindParam(':plataforma', $plataforma, PDO::PARAM_STR);
	$SQL->execute(); 
}

function DownloadAtualizacao($arquivo, $fullpath){
		
	$ch = curl_init ($arquivo);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_BINARYTRANSFER,1);
	$rawdata=curl_exec($ch);
	curl_close ($ch);
		if(file_exists($fullpath)){
    		unlink($fullpath);
		}
	$fp = fopen($fullpath,'x');
	fwrite($fp, $rawdata);
	fclose($fp);
	 
	}

function VerificarUsuarioEditar($usuario, $id=NULL, $acesso){
	include("conexao.php");
	
	if($acesso == 1){
		$SQL = empty($id) ? "SELECT usuario FROM admin WHERE usuario = :usuario" : "SELECT usuario FROM admin WHERE usuario = :usuario AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		if(!empty($id)) $SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM usuario WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM teste WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 2){
		$SQL = empty($id) ? "SELECT usuario FROM rev WHERE usuario = :usuario" : "SELECT usuario FROM rev WHERE usuario = :usuario AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		if(!empty($id)) $SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM admin WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM usuario WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM teste WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 3){
		$SQL = empty($id) ? "SELECT usuario FROM usuario WHERE usuario = :usuario" : "SELECT usuario FROM usuario WHERE usuario = :usuario AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		if(!empty($id)) $SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM admin WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM teste WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 4){
		$SQL = empty($id) ? "SELECT usuario FROM teste WHERE usuario = :usuario" : "SELECT usuario FROM teste WHERE usuario = :usuario AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		if(!empty($id)) $SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM admin WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT usuario FROM usuario WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
		
		return 2;
}


function VerificarEmailEditar($email, $id, $acesso){
	include("conexao.php");
	
	if($acesso == 1){
		$SQL = "SELECT email FROM admin WHERE email = :email AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM rev WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM usuario WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM teste WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 2){
		$SQL = "SELECT email FROM rev WHERE email = :email AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM admin WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM usuario WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM teste WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 3){
		$SQL = "SELECT email FROM usuario WHERE email = :email AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM admin WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM rev WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM teste WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
			return 2;
	}
	
	elseif($acesso == 4){
		$SQL = "SELECT email FROM teste WHERE email = :email AND id != :id";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->bindParam(':id', $id, PDO::PARAM_INT);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM admin WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM rev WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
	
		$SQL = "SELECT email FROM usuario WHERE email = :email";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
	
		if($Total > 0) {
			return 1;
		}
			return 2;
	}
		return 2;
}

function ArvoreAdminRev($CadUser){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM admin WHERE CadUser = :CadUser UNION ALL SELECT usuario FROM rev WHERE CadUser = :CadUser ORDER by usuario ASC";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
		while($LnSelect = $SQL->fetch()){
			if($LnSelect['usuario'] != $CadUser){
				$Arvore[] = $LnSelect['usuario'];
				$SomarArvore = ArvoreAdminRev($LnSelect['usuario']);
				$Arvore = array_merge($Arvore, $SomarArvore);
			}
		}
	}
	
	return array_values(array_unique($Arvore));
}

function ArvoreAdmin($CadUser){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM admin WHERE CadUser = :CadUser ORDER by usuario ASC";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
	while($LnSelect = $SQL->fetch()){
		if($LnSelect['usuario'] != $CadUser){
		$Arvore[] = $LnSelect['usuario'];
		$SomarArvore = ArvoreAdmin($LnSelect['usuario']);
		$Arvore = array_merge($Arvore, $SomarArvore);
		}
	}
	}
	
	return array_values(array_unique($Arvore));
}

function ArvoreRev($CadUser){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM rev WHERE CadUser = :CadUser ORDER by usuario ASC";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
	while($LnSelect = $SQL->fetch()){
		if($LnSelect['usuario'] != $CadUser){
		$Arvore[] = $LnSelect['usuario'];
		$SomarArvore = ArvoreRev($LnSelect['usuario']);
		$Arvore = array_merge($Arvore, $SomarArvore);
		}
	}
	}
	
	return array_values(array_unique($Arvore));
}

function ArvoreUser($CadUser){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM usuario WHERE CadUser = :CadUser ORDER by usuario ASC";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
	while($LnSelect = $SQL->fetch()){
		if($LnSelect['usuario'] != $CadUser){
		$Arvore[] = $LnSelect['usuario'];
		$SomarArvore = ArvoreUser($LnSelect['usuario']);
		$Arvore = array_merge($Arvore, $SomarArvore);
		}
	}
	}
	
	return array_values(array_unique($Arvore));
}

function ArvoreCadUser($usuario){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "(SELECT CadUser, bloqueado, inativo, data_premio FROM rev WHERE usuario = :usuario) UNION ALL (SELECT CadUser, bloqueado, inativo, null FROM admin WHERE usuario = :usuario)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
		while($LnSelect = $SQL->fetch()){
			$Arvore[] = array($usuario, $LnSelect['bloqueado'], $LnSelect['inativo'], $LnSelect['data_premio'], $LnSelect['CadUser']);
			if($LnSelect['CadUser'] != $usuario){
				$SomarArvore = ArvoreCadUser($LnSelect['CadUser']);
				$Arvore = array_merge($Arvore, $SomarArvore);
			}
		}
	}
	
	return $Arvore;
}

function UpdateUserXML($usuario, $xml){	
	include("conexao.php");
	
	$SQL = "UPDATE usuario SET
			xml = :xml
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);                                  
	$SQL->bindValue(':xml', $xml); 
	$SQL->bindValue(':usuario', $usuario); 
	$SQL->execute();
	
	$SQL = "UPDATE teste SET
			xml = :xml
            WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);                                  
	$SQL->bindValue(':xml', $xml); 
	$SQL->bindValue(':usuario', $usuario); 
	$SQL->execute();
}

function VerificarBlockAcesso($usuario){
	include("conexao.php");
	$DataAtual = strtotime(date('Y-m-d'));

		$ArvoreCadUser = ArvoreCadUser($usuario);
						
		for($i = 0; $i < count($ArvoreCadUser); $i++){
			$usuario = $ArvoreCadUser[$i][0];
			$bloqueado = $ArvoreCadUser[$i][1];
			$inativo = $ArvoreCadUser[$i][2];
			$data_premio = $ArvoreCadUser[$i][3];
			$CadUser = $ArvoreCadUser[$i][4];
			
			if($bloqueado == "S"){
				$_SESSION['VerificarBlockAcesso'] = 1;
				return 1;
			}
			elseif($inativo == "S"){
				$_SESSION['VerificarBlockAcesso'] = 2;
				return 2;
			}
			elseif($usuario == $CadUser){
				$_SESSION['VerificarBlockAcesso'] = 4;
				return 4;
			}
			elseif( !empty($data_premio) && ($data_premio < $DataAtual) ){
				$_SESSION['VerificarBlockAcesso'] = 3;
				return 3;
			}
		}
	
	$_SESSION['VerificarBlockAcesso'] = 4;
	return 4;
	
}

function VerificarBlockArvore($CadUser, $usuario){
	include("conexao.php");
	$DataAtual = strtotime(date('Y-m-d'));
 
		$ArvoreCadUser = ArvoreCadUser($CadUser);
						
		for($i = 0; $i < count($ArvoreCadUser); $i++){
			$usuario = $ArvoreCadUser[$i][0];
			$bloqueado = $ArvoreCadUser[$i][1];
			$inativo = $ArvoreCadUser[$i][2];
			$data_premio = $ArvoreCadUser[$i][3];
			$CadUser = $ArvoreCadUser[$i][4];
			
			if($bloqueado == "S"){
				return 1;
			}
			elseif($inativo == "S"){
				return 2;
			}
			elseif($usuario == $CadUser){
				return 4;
			}
			elseif( !empty($data_premio) && ($data_premio < $DataAtual) ){
				return 3;
			}
		}
			
	return 4;
	
}

function ArvoreTeste($CadUser){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM teste WHERE CadUser = :CadUser";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
	while($LnSelect = $SQL->fetch()){
		if($LnSelect['usuario'] != $CadUser){
		$Arvore[] = $LnSelect['usuario'];
		$SomarArvore = ArvoreTeste($LnSelect['usuario']);
		$Arvore = array_merge($Arvore, $SomarArvore);
		}
	}
	}
	
	return array_values(array_unique($Arvore));
}

function SelecionarPerfilNome($Perfil){	
	include("conexao.php");
	$UserOnline = InfoUser(2);
	$NewPerfil = "";
	
	$id_imagem = "";
	$valorcsp = str_replace('][','],[',$Perfil);
		
		$SQLPerfil = "SELECT id, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp)";
		$SQLPerfil = $painel_geral->prepare($SQLPerfil);
		$SQLPerfil->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR);
		$SQLPerfil->execute();
		$MaskaraAtual = "";
		while($LnPerfil = $SQLPerfil->fetch()){
			$MaskPerfil = MaskPerfil($UserOnline, $LnPerfil['id']);
			$MaskaraAtual .= $MaskPerfil[0]."; ";
		}
		$MaskaraAtual = trim($MaskaraAtual);
		
		$NewPerfil .= $MaskaraAtual;
			
	return $NewPerfil;
}

function SelecionarPerfil($Perfil){	
	include("conexao.php");
	$UserOnline = InfoUser(2);
	$NewPerfil = "";
	
	$id_imagem = "";
	$valorcsp = str_replace('][','],[',$Perfil);
	$SQL = "SELECT DISTINCT(imagem) FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR);
	$SQL->execute();
	while($Ln = $SQL->fetch()){
		
		$SQLImg = "SELECT img FROM perfil_icone WHERE id = :id";
		$SQLImg = $painel_geral->prepare($SQLImg);
		$SQLImg->bindParam(':id', $Ln['imagem'], PDO::PARAM_STR);
		$SQLImg->execute();
		$LnImg = $SQLImg->fetch();
		$FotoPerfil = FotoPerfil($LnImg['img']);
		
		$SQLPerfil = "SELECT id, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND imagem = :imagem";
		$SQLPerfil = $painel_geral->prepare($SQLPerfil);
		$SQLPerfil->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR);
		$SQLPerfil->bindParam(':imagem', $Ln['imagem'], PDO::PARAM_STR);
		$SQLPerfil->execute();
		$MaskaraAtual = "";
		while($LnPerfil = $SQLPerfil->fetch()){
			$MaskPerfil = MaskPerfil($UserOnline, $LnPerfil['id']);
			$MaskaraAtual .= $MaskPerfil[0]."; ";
		}
		$MaskaraAtual = trim($MaskaraAtual);
		
		$NewPerfil .= "<span style=\"padding:0px 5px 0px 0px;\" data-trigger=\"hover\" data-placement=\"top\" class=\"label pointer popover-dismiss\" title=\"\" data-content=\"".$MaskaraAtual."\"><img src=\"".$FotoPerfil."\" alt=\"".$MaskaraAtual."\" height=\"16\" width=\"16\"></span>";
		
	}
	
	return $NewPerfil;
}

function UrlAtual(){
 $dominio= $_SERVER['HTTP_HOST'];
 $rest = $_SERVER['REQUEST_URI'];
 $ex = explode("/", $rest);
 $e = end($ex);
 $pasta = str_replace($e,"",$rest);
 $url = "http://" . $dominio.$pasta;
 return $url;
 }
 
 function DeletarPerfil($valorcsp, $banco){
	include("conexao.php");
	
	$SQLUser = "SELECT id, perfil FROM ".$banco." WHERE perfil != '' AND perfil LIKE '%".$valorcsp."%'";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->execute();
		while($LnUser = $SQLUser->fetch()){
			
			$perfil = str_replace($valorcsp,"",$LnUser['perfil']);
			
			$SQLPerfil = "SELECT valorcsp FROM perfil WHERE valorcsp = :valorcsp";
			$SQLPerfil = $painel_geral->prepare($SQLPerfil);
			$SQLPerfil->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR);
			$SQLPerfil->execute();
			$TotalPerfil = count($SQLPerfil->fetchAll());
						
				if($TotalPerfil > 1){
					$perfil = $perfil.$valorcsp;
				}
				else{
					$perfil = $perfil;
				}
			
			$SQL = "UPDATE ".$banco." SET
			perfil = :perfil
       	 	WHERE id = :id";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':perfil', $perfil, PDO::PARAM_STR); 
			$SQL->bindParam(':id', $LnUser['id'], PDO::PARAM_INT); 
			$SQL->execute();
		}
	}
	
function EditarPerfil($valorcsp, $novocsp, $banco){
		include("conexao.php");
		
		$SQLUser = "SELECT id, perfil FROM ".$banco." WHERE perfil != '' AND perfil LIKE '%".$valorcsp."%'";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->execute();
		
		while($LnUser = $SQLUser->fetch()){
						
			$perfil = str_replace($valorcsp,"",$LnUser['perfil']);
			
			if(substr_count($perfil, $novocsp) > 0){
				$perfil = $perfil;
			}
			else{
				
				$SQLPerfil = "SELECT valorcsp FROM perfil WHERE valorcsp = :valorcsp";
				$SQLPerfil = $painel_geral->prepare($SQLPerfil);
				$SQLPerfil->bindParam(':valorcsp', $valorcsp, PDO::PARAM_STR);
				$SQLPerfil->execute();
				$TotalPerfil = count($SQLPerfil->fetchAll());
				
				if($TotalPerfil > 1){
					$perfil = $perfil.$novocsp.$valorcsp;
				}
				else{
					$perfil = $perfil.$novocsp;
				}
			}
									
			$SQL = "UPDATE ".$banco." SET
				perfil = :perfil
       	 		WHERE id = :id";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':perfil', $perfil, PDO::PARAM_STR); 
			$SQL->bindParam(':id', $LnUser['id'], PDO::PARAM_INT); 
			$SQL->execute();
		}
}

function VerificarPerfil($valorcsp){
	include("conexao.php");
	
	$SQLUser = "SELECT id, perfil FROM admin WHERE perfil != '' AND perfil LIKE '%".$valorcsp."%'";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->execute();
	$TotalPerfil = count($SQLUser->fetchAll());
	
	return $TotalPerfil;
}

function PerfilSelect($CadUser){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	//CadUser
	$PerfilCad = array();
	
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
	
	$bloqueado = "N";
	$Perfil = "<li><a perfil=\"Todos\" nome=\"".$_TRA['Todos']."\" class=\"ExibirPerfil pointer\">".$_TRA['Todos']."</a></li>";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
		
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				$Perfil .= "<li><a perfil=\"".$LnPerfil['valorcsp']."\" nome=\"".$MaskPerfil[0]."\" class=\"ExibirPerfil pointer\">".$MaskPerfil[0]."</a></li>";	
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<li>".$_TRA['nepc']."</li>";
	return $Perfil;
}

function PerfilSelectStatus($CadUser){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	//CadUser
	$PerfilCad = array();
	
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
	
	$bloqueado = "N";
	$Perfil = "<option value=\"T\">".$_TRA['Todos']."</option>";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
		
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				$Perfil .= "<option value=\"".$LnPerfil['valorcsp']."\">".$MaskPerfil[0]."</option>";	
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<option value=\"T\">".$_TRA['nepc']."</option>";
	return $Perfil;
}

function PerfilSelectMascara($CadUser){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	//CadUser
	$PerfilCad = array();
	
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
	
	$bloqueado = "N";
	$Perfil = "";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
		
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				
				$bloqueado = "N";
				$SQLCSP = "SELECT id FROM perfil WHERE bloqueado = :bloqueado AND valorcsp = :valorcsp ORDER by nome ASC";
				$SQLCSP = $painel_geral->prepare($SQLCSP);
				$SQLCSP->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
				$SQLCSP->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
				$SQLCSP->execute();
					
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				while($LnCSP = $SQLCSP->fetch()){
					
					$bloqueado = "N";
					$SQLVerMask = "SELECT id FROM mascaraurl WHERE bloqueado = :bloqueado AND perfil = :perfil AND CadUser = :CadUser";
					$SQLVerMask = $painel_geral->prepare($SQLVerMask);
					$SQLVerMask->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
					$SQLVerMask->bindParam(':perfil', $LnCSP['id'], PDO::PARAM_STR);
					$SQLVerMask->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
					$SQLVerMask->execute();
					$TotalVerMask = count($SQLVerMask->fetchAll());
					
					if($TotalVerMask < 1){
						$MaskPerfil = MaskPerfil($CadUser, $LnCSP['id']);
						$Perfil .= "<option value=\"".$LnCSP['id']."\">".$MaskPerfil[0]."</option>";
					}
				}
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<option value=\"T\">".$_TRA['nepc']."</option>";
	return $Perfil;
}

function PerfilSelectMascaraEdit($CadUser, $id){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$SQLMask = "SELECT perfil FROM mascaraurl WHERE CadUser = :CadUser AND id = :id";
	$SQLMask = $painel_geral->prepare($SQLMask);
	$SQLMask->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLMask->bindParam(':id', $id, PDO::PARAM_STR);
	$SQLMask->execute();
	$LnMask = $SQLMask->fetch();
	$IDperfil = $LnMask['perfil'];
	
	//CadUser
	$PerfilCad = array();
	
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
	
	$bloqueado = "N";
	$Perfil = "";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
		
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				
				$bloqueado = "N";
				$SQLCSP = "SELECT id FROM perfil WHERE bloqueado = :bloqueado AND valorcsp = :valorcsp AND id = :id ORDER by nome ASC";
				$SQLCSP = $painel_geral->prepare($SQLCSP);
				$SQLCSP->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
				$SQLCSP->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
				$SQLCSP->bindParam(':id', $IDperfil, PDO::PARAM_STR);
				$SQLCSP->execute();
				$LnCSP = $SQLCSP->fetch();
				$MaskPerfil = MaskPerfil($CadUser, $LnCSP['id']);
				$Perfil .= "<option value=\"".$LnCSP['id']."\">".$MaskPerfil[0]."</option>";
				
				$SQLCSP2 = "SELECT id FROM perfil WHERE bloqueado = :bloqueado AND valorcsp = :valorcsp AND id != :id ORDER by nome ASC";
				$SQLCSP2 = $painel_geral->prepare($SQLCSP2);
				$SQLCSP2->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
				$SQLCSP2->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
				$SQLCSP2->bindParam(':id', $IDperfil, PDO::PARAM_STR);
				$SQLCSP2->execute();
					
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				while($LnCSP2 = $SQLCSP2->fetch()){
					$MaskPerfil2 = MaskPerfil($CadUser, $LnCSP2['id']);
					$Perfil .= "<option value=\"".$LnCSP2['id']."\">".$MaskPerfil2[0]."</option>";	
				}
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<option value=\"T\">".$_TRA['nepc']."</option>";
	return $Perfil;
}


function PerfilAdminEditar($CadUser, $Usuario, $tipo){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;

	if($tipo == 1){
		$banco = "admin";
	}
	elseif($tipo == 2){
		$banco = "rev";
	}
	elseif($tipo == 3){
		$banco = "usuario";
	}
	elseif($tipo == 4){
		$banco = "teste";
	}
		
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
		
	$bloqueado = "N";
	$Perfil = "";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();

	$SQLUser = "SELECT perfil FROM ".$banco." WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $Usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				$ckecked = substr_count($LnUser['perfil'], $LnPerfil['valorcsp']) > 0 ? "checked=\"checked\"" : "";
				$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
				$Perfil .= "<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EditarPerfil[]\" id=\"EditarPerfil[]\" value=\"".$LnPerfil['valorcsp']."\" type=\"checkbox\" class=\"icheckbox\" ".$ckecked." /> ".$MaskPerfil[0]."</label></div>";	
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<div style=\"border:0px;\" class=\"col-md-5\"><label class=\"check\">".$_TRA['nepc']."</label></div>";
	return $Perfil;
}

function PerfilCriarPlano($CadUser, $perfil = NULL){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
		
	$SQLCad = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
		
	$bloqueado = "N";
	$Perfil = "";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
	
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				$ckecked = substr_count($perfil, $LnPerfil['valorcsp']) > 0 ? "checked=\"checked\"" : "";
				$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
				$Perfil .= "<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EditarPerfil[]\" id=\"EditarPerfil[]\" value=\"".$LnPerfil['valorcsp']."\" type=\"checkbox\" class=\"icheckbox\" ".$ckecked." /> ".$MaskPerfil[0]."</label></div>";	
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<div style=\"border:0px;\" class=\"col-md-5\"><label class=\"check\">".$_TRA['nepc']."</label></div>";
	return $Perfil;
}

function SelecionarAcessos($tabela, $user, $grupo, $id_grupo = NULL){
	include("conexao.php");
		
	$exibirGrupo = $grupo == "S" ? " AND id_grupo = :id_grupo" : "";
		
	$SQLAcessos = "SELECT * FROM ".$tabela." WHERE CadUser = :CadUser AND grupo = :grupo".$exibirGrupo;
	$SQLAcessos = $painel_acessos->prepare($SQLAcessos);
	$SQLAcessos->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLAcessos->bindParam(':grupo', $grupo, PDO::PARAM_STR); 
	
		if($grupo == "S"){
		$SQLAcessos->bindParam(':id_grupo', $id_grupo, PDO::PARAM_INT); 
		}
	
	$SQLAcessos->execute();
	
	return $SQLAcessos->fetch();
}

function InserirCheckbox($array, $Tabela){
	$Perfil = "";
	
	$ColunaAdmin = array();
	for($i = 0; $i < count($array); $i++){
		$ColunaAdmin[] = $array[$i][0];
	}
	
	VerificarAcesso($Tabela, $ColunaAdmin);
	
	for($i = 0; $i < count($array); $i++){
	if($_SESSION[$array[$i][0]] == "S"){
	$valor = empty($array[$i][2]) ? "N" : $array[$i][2];	
	$ckecked = $valor == "S" ? "checked=\"checked\"" : "";
	$Perfil .= "<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-4\"><label class=\"check\"><input name=\"".$array[$i][0]."\" id=\"".$array[$i][0]."\" type=\"checkbox\" class=\"icheckbox\" ".$ckecked." /> ".$array[$i][1]."</label></div>";
	}
	}
	
	return $Perfil;
}

function SelecionarLeiaute(){
	include("conexao.php");
	
	if( isset($_SESSION['leiaute']) && isset($_SESSION['wall']) && isset($_SESSION['cabecalho']) && isset($_SESSION['barralateral']) && isset($_SESSION['scroll']) && isset($_SESSION['barradireita']) && isset($_SESSION['navpersonalizado']) && isset($_SESSION['alternarnav']) && isset($_SESSION['minimizar']) ){
		return array($_SESSION['leiaute'] , $_SESSION['wall'], $_SESSION['cabecalho'], $_SESSION['barralateral'], $_SESSION['scroll'], $_SESSION['barradireita'], $_SESSION['navpersonalizado'], $_SESSION['alternarnav'], $_SESSION['minimizar']);
	}
	else{
	
	$user = InfoUser(2);	
	$SQLLeiaute = "SELECT leiaute, wall, cabecalho, barralateral, scroll, barradireita, navpersonalizado, alternarnav, minimizar FROM leiaute WHERE CadUser = :CadUser";
	$SQLLeiaute = $painel_geral->prepare($SQLLeiaute);
	$SQLLeiaute->bindParam(':CadUser', $user, PDO::PARAM_STR); 
	$SQLLeiaute->execute();
	$LnLeiaute = count($SQLLeiaute->fetchAll());
	
	if($LnLeiaute > 0){
		$SQLLeiaute->execute();
		$LnLeiaute = $SQLLeiaute->fetch();
		
		$leiaute = empty($LnLeiaute['leiaute']) ? 0 : $LnLeiaute['leiaute'];
		$wall = empty($LnLeiaute['wall']) ? 'wall_1' : $LnLeiaute['wall'];
		$cabecalho = empty($LnLeiaute['cabecalho']) ? 0 : $LnLeiaute['cabecalho'];
		$barralateral = empty($LnLeiaute['barralateral']) ? 1 : $LnLeiaute['barralateral'];
		$scroll = empty($LnLeiaute['scroll']) ? 1 : $LnLeiaute['scroll'];
		$barradireita = empty($LnLeiaute['barradireita']) ? 0 : $LnLeiaute['barradireita'];
		$navpersonalizado = empty($LnLeiaute['navpersonalizado']) ? 0 : $LnLeiaute['navpersonalizado'];
		$alternarnav = empty($LnLeiaute['alternarnav']) ? 0 : $LnLeiaute['alternarnav'];
		$minimizar = empty($LnLeiaute['minimizar']) ? "N" : $LnLeiaute['minimizar'];
		
		$_SESSION['leiaute'] = $leiaute;
		$_SESSION['wall'] = $wall;
		$_SESSION['cabecalho'] = $cabecalho;
		$_SESSION['barralateral'] = $barralateral;
		$_SESSION['scroll'] = $scroll;
		$_SESSION['barradireita'] = $barradireita;
		$_SESSION['navpersonalizado'] = $navpersonalizado;
		$_SESSION['alternarnav'] = $alternarnav;
		$_SESSION['minimizar'] = $minimizar;
		
		return array($leiaute , $wall, $cabecalho, $barralateral, $scroll, $barradireita, $navpersonalizado, $alternarnav, $minimizar);
	}
	else{
		
		$_SESSION['leiaute'] = 0;
		$_SESSION['wall'] = 'wall_1';
		$_SESSION['cabecalho'] = 0;
		$_SESSION['barralateral'] = 1;
		$_SESSION['scroll'] = 1;
		$_SESSION['barradireita'] = 0;
		$_SESSION['navpersonalizado'] = 0;
		$_SESSION['alternarnav'] = 0;
		$_SESSION['minimizar'] = 'N';
		
		return array(0, 'wall_1', 0, 1, 1, 0, 0, 0, 'N');
	}
	
	}
}


function ExcluirPorUsuario($CadUser){
	include("conexao.php");
	
	//painel_acessos 
	$SQL = "SHOW TABLES";
	$SQL = $painel_acessos->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_acessos->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
		$SQLDel = "DELETE FROM ".$Ln[0]." WHERE CadUser = :CadUser";
		$SQLDel = $painel_acessos->prepare($SQLDel);
		$SQLDel->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQLDel->execute();
		}
	}
	
	//painel_geral 
	$SQL = "SHOW TABLES";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_geral->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
		$SQLDel = "DELETE FROM ".$Ln[0]." WHERE CadUser = :CadUser";
		$SQLDel = $painel_geral->prepare($SQLDel);
		$SQLDel->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQLDel->execute();
		}
	}
	
	//painel_user 
	$SQL = "SHOW TABLES";
	$SQL = $painel_user->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_user->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
		$SQLDel = "DELETE FROM ".$Ln[0]." WHERE CadUser = :CadUser";
		$SQLDel = $painel_user->prepare($SQLDel);
		$SQLDel->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQLDel->execute();
		}
	}
	
	return 1;	
}

function BloquearDesbloquearArvore($CadUser, $status){
	include("conexao.php");
	
	$ArvoreAdmin = ArvoreAdmin($CadUser);
	for($i = 0; $i < count($ArvoreAdmin); $i++){
		$SQL = "UPDATE admin SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':bloqueado', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreAdmin[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
	$ArvoreRev = ArvoreRev($CadUser);
	for($i = 0; $i < count($ArvoreRev); $i++){
		$SQL = "UPDATE rev SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':bloqueado', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreRev[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
	$ArvoreUser = ArvoreUser($CadUser);
	for($i = 0; $i < count($ArvoreUser); $i++){
		$SQL = "UPDATE usuario SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':bloqueado', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreUser[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
	$ArvoreTeste = ArvoreTeste($CadUser);
	for($i = 0; $i < count($ArvoreTeste); $i++){
		$SQL = "UPDATE teste SET
			bloqueado = :bloqueado
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':bloqueado', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreTeste[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
}

function DesativarAtivarArvore($CadUser, $status){
	include("conexao.php");
	
	$ArvoreAdmin = ArvoreAdmin($CadUser);
	for($i = 0; $i < count($ArvoreAdmin); $i++){
		$SQL = "UPDATE admin SET
			inativo = :inativo
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':inativo', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreAdmin[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
	$ArvoreRev = ArvoreRev($CadUser);
	for($i = 0; $i < count($ArvoreRev); $i++){
		$SQL = "UPDATE rev SET
			inativo = :inativo
            WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':inativo', $status, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $ArvoreRev[$i], PDO::PARAM_STR); 
		$SQL->execute(); 
	}
	
}

function ConverterCheckbox($tag){
	if($tag == "on"){
		return "S";
	}
	else{
		return "N";
	}
}

function AtualizarAcessos($ArrayAdmin, $TabelaAdmin, $ColunaAdmin, $CadUser, $grupo, $id_grupo = NULL){
	include("conexao.php");
		
	$GrupoVer = $grupo == "S" ? " AND id_grupo = :id_grupo" : "";
			
	$SQLTable = "SELECT * FROM ".$TabelaAdmin." WHERE CadUser = :CadUser AND grupo = :grupo".$GrupoVer;
	$SQLTable = $painel_acessos->prepare($SQLTable);
	$SQLTable->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQLTable->bindParam(':grupo', $grupo, PDO::PARAM_STR); 
	if($grupo == "S") $SQLTable->bindParam(':id_grupo', $id_grupo, PDO::PARAM_STR); 
	$SQLTable->execute();
	$TotalTable = count($SQLTable->fetchAll());
		
	if($TotalTable > 0){
		
			$TabelaExibir = "";
			for($is = 0; $is < count($ColunaAdmin); $is++){
				$TabelaExibir .= "".$ColunaAdmin[$is]." = :".$ColunaAdmin[$is];
				if($is < (count($ColunaAdmin) - 1)) $TabelaExibir .= ", ";
			}
						
			$GrupoExibir = $grupo == "S" ? " AND id_grupo = :id_grupo" : "";
			$TabelaExibir = trim($TabelaExibir);
		
			$SQL = "UPDATE ".$TabelaAdmin." SET ".$TabelaExibir."
            WHERE CadUser = :CadUser AND grupo = :grupo".$GrupoExibir;
			$SQL = $painel_acessos->prepare($SQL);
			$SQL->bindParam(':grupo', $grupo, PDO::PARAM_STR);
			
				if($grupo == "S"){
					$SQL->bindParam(':id_grupo', $id_grupo, PDO::PARAM_INT);
				}
				
				for($is = 0; $is < count($ColunaAdmin); $is++){
					$SQL->bindParam(':'.$ColunaAdmin[$is].'', $ArrayAdmin[$is], PDO::PARAM_STR); 
				}
			$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
			$SQL->execute(); 
			
			if(empty($SQL)){
				return false;
			}
			else{
				return true;
			}
			
		}
		else{
			
			$GrupoExibir = $grupo == "S" ? "grupo, id_grupo," : "";
			$GrupoExibir2 = $grupo == "S" ? ":grupo, :id_grupo," : "";
			
			$TabelaExibir = "";
			$TabelaExibir2 = "";
			for($is = 0; $is < count($ColunaAdmin); $is++){
			$TabelaExibir .= $ColunaAdmin[$is];
			$TabelaExibir2 .= ":".$ColunaAdmin[$is];
				if($is < (count($ColunaAdmin) - 1)){ 
				$TabelaExibir .= ", ";
				$TabelaExibir2 .= ", ";
				}
			}
			

			$SQL = "INSERT INTO ".$TabelaAdmin." (".$GrupoExibir." CadUser, ".$TabelaExibir.") VALUES (".$GrupoExibir2." :CadUser, ".$TabelaExibir2.")";
			$SQL = $painel_acessos->prepare($SQL);
			
				if($grupo == "S"){
					$SQL->bindParam(':grupo', $grupo, PDO::PARAM_STR);
					$SQL->bindParam(':id_grupo', $id_grupo, PDO::PARAM_INT);
				}
			
			$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
			
			for($is = 0; $is < count($ColunaAdmin); $is++){
				$SQL->bindParam(':'.$ColunaAdmin[$is].'', $ArrayAdmin[$is], PDO::PARAM_STR); 
			}
			
			$SQL->execute(); 
			
			if(empty($SQL)){
				return false;
			}
			else{
				return true;
			}
		}
	}
	
function SelecionarPerfilAdminRev($perfil){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	$UserOnline = InfoUser(2);
	
	$Exibir = "";
	
	$ex = explode('[',$perfil);
	for($i = 1; $i < count($ex); $i++){
	$Perfil = "[".$ex[$i];
	
		$SQL = "SELECT perfil_icone.img, perfil.id FROM perfil_icone INNER JOIN perfil ON perfil_icone.id = perfil.imagem AND perfil.valorcsp = :perfil";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':perfil', $Perfil, PDO::PARAM_STR);
		$SQL->execute();
		$LnSelect = $SQL->fetch();
	
		$FotoPerfil = FotoPerfil($LnSelect['img']);
		$MaskPerfil = MaskPerfil($UserOnline, $LnSelect['id']);
		
		$Exibir .= "<img src='".$FotoPerfil."' width='16' height='16'>"." ".$MaskPerfil[0];
		$Exibir .= "; ";
	}
	
		
	$return = "<span type=\"button\" data-trigger=\"hover\" data-placement=\"top\" class=\"label label-default pointer popover-dismiss\" title=\"\" data-content=\"".$Exibir."\" data-original-title=\"".$_TRA['Perfil']."\">".$_TRA['Perfil']."</span>";
	
	return $return;
		
}
	
function VerificarAcesso($Tabela, $ColunaAdmin){
	include("conexao.php");
	$CadUser = InfoUser(2);
	$grupo = "N";
	$Arrays = array();

	$VerificarComputadorLiberado = VerificarComputadorLiberado();
	$ComputadorLiberado = empty($_COOKIE['ComputadorLiberado']) ? "" : $_COOKIE['ComputadorLiberado'];

	if($VerificarComputadorLiberado[0] == "S"){

		$SomarLib = 0;
		for($i=0; $i<count($VerificarComputadorLiberado[1]); $i++){
			if( $VerificarComputadorLiberado[1][$i] == $ComputadorLiberado ){
				$SomarLib += 1;
			}
		}

		if($SomarLib == 0){
			echo Redirecionar('lib-computador.php');
			return false;
		}

	}

	$VerificarBlockAcesso = empty($_SESSION['VerificarBlockAcesso']) ? VerificarBlockAcesso($CadUser) : $_SESSION['VerificarBlockAcesso'];


	if($VerificarBlockAcesso != 4){
		return false;
	}
	else{

	for($ix = 0; $ix < count($ColunaAdmin); $ix++){
		if(isset($_SESSION[$ColunaAdmin[$ix]])) {
			$Arrays[] = $_SESSION[$ColunaAdmin[$ix]];
			continue;
		}

	$TabelaExibir = "";
	for($is = 0; $is < count($ColunaAdmin); $is++){
		$TabelaExibir .= $ColunaAdmin[$is]."";
		if($is < (count($ColunaAdmin) - 1)) $TabelaExibir .= ", ";
	}

	$SQLTable = "SELECT ".$TabelaExibir." FROM ".$Tabela." WHERE CadUser = :CadUser AND grupo = :grupo";
	$SQLTable = $painel_acessos->prepare($SQLTable);
	$SQLTable->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLTable->bindParam(':grupo', $grupo, PDO::PARAM_STR);
	$SQLTable->execute();
	$TotalTable = count($SQLTable->fetchAll());

	if($TotalTable > 0){
		$SQLTable->execute();
		$LnTable = $SQLTable->fetch();

		$Array = array();
		for($is = 0; $is < count($ColunaAdmin); $is++){
			$Array[] = $LnTable[$ColunaAdmin[$is]];
			$_SESSION[$ColunaAdmin[$is]] = $LnTable[$ColunaAdmin[$is]];
		}

		return $Array;

	}
	else{

		$Array = array();
		for($is = 0; $is < count($ColunaAdmin); $is++){
			$Array[] = 'N';
			$_SESSION[$ColunaAdmin[$is]] = 'N';
		}
		return $Array;

	}

	}
		return $Arrays;
	}
}
function MensagemBox($tipo, $titulo, $mensagem){
	include_once(Idioma(1));
	global $_TRA;
		
	return "<div class=\"alert alert-".$tipo."\" role=\"alert\"><button type=\"button\" class=\"close\" data-dismiss=\"alert\"><span aria-hidden=\"true\">×</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button><strong>".$titulo."!</strong> ".$mensagem."</div>";
	
}

function SelecionarModeloPreferencias($tipo, $Coluna){
include("conexao.php");
include_once(Idioma(1));
global $_TRA;
$CadUser = InfoUser(2);
$option = "";

$SQL = "SELECT ".$Coluna." FROM email_preferencias WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();
$Total = count($SQL->fetchAll());

$SQL->execute();
$Ln = $SQL->fetch();
$Selecao = empty($Ln[$Coluna]) ? "" : $Ln[$Coluna];

if(empty($Selecao)){
	$SQL = "SELECT id, assunto FROM email_modelo WHERE CadUser = :CadUser AND tipo = :tipo ORDER BY assunto ASC";
}
else{
	$SQL = "SELECT id, assunto FROM email_modelo WHERE CadUser = :CadUser AND tipo = :tipo ORDER BY FIELD(id, :id) DESC, assunto ASC";
}

	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR); 
	if(!empty($Selecao)) $SQL->bindParam(':id', $Selecao, PDO::PARAM_INT); 
	$SQL->execute();
	
	if($Total < 1){
		$option = "<option value=\"0\">-- ".$_TRA['suo']." --</option>";
	}
	while($Ln = $SQL->fetch()){
		$option .= "<option value=\"".$Ln['id']."\">".$Ln['assunto']."</option>";
	}

	
return $option;

}

function SelecionarModeloPreferenciasSMS($tipo, $Coluna){
include("conexao.php");
include_once(Idioma(1));
global $_TRA;
$CadUser = InfoUser(2);
$option = "";

$SQL = "SELECT ".$Coluna." FROM sms_preferencias WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();
$Total = count($SQL->fetchAll());

$SQL->execute();
$Ln = $SQL->fetch();
$Selecao = empty($Ln[$Coluna]) ? "" : $Ln[$Coluna];

if(empty($Selecao)){
	$SQL = "SELECT id, assunto FROM sms_modelo WHERE CadUser = :CadUser AND tipo = :tipo ORDER BY assunto ASC";
}
else{
	$SQL = "SELECT id, assunto FROM sms_modelo WHERE CadUser = :CadUser AND tipo = :tipo ORDER BY FIELD(id, :id) DESC, assunto ASC";
}

	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR); 
	if(!empty($Selecao)) $SQL->bindParam(':id', $Selecao, PDO::PARAM_INT); 
	$SQL->execute();
	
	if($Total < 1){
		$option = "<option value=\"0\">-- ".$_TRA['suo']." --</option>";
	}
	while($Ln = $SQL->fetch()){
		$option .= "<option value=\"".$Ln['id']."\">".$Ln['assunto']."</option>";
	}

	
return $option;

}

function VerificarInfoSite(){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	if( isset($_SESSION['NomePainel']) && isset($_SESSION['LegendaPainel']) && isset($_SESSION['TemaPainel']) ){
		return array($_SESSION['NomePainel'], $_SESSION['LegendaPainel'], $_SESSION['TemaPainel']);
	}
	else{
		$SQL = "SELECT NomePainel, LegendaPainel, TemaPainel FROM site_config";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->execute();
		$Total = count($SQL->fetchAll());
		
		if($Total > 0){
			$SQL->execute();
			$Ln = $SQL->fetch();
			$NomePainel = empty($Ln['NomePainel']) ? "CSPainel" : $Ln['NomePainel'];
			$LegendaPainel = empty($Ln['LegendaPainel']) ? $_TRA['gdp'] : $Ln['LegendaPainel'];
			$TemaPainel = empty($Ln['TemaPainel']) ? "theme-default" : $Ln['TemaPainel'];
			
			$_SESSION['NomePainel'] = $NomePainel;
			$_SESSION['LegendaPainel'] = $LegendaPainel;
			$_SESSION['TemaPainel'] = $TemaPainel;
			
			return array($NomePainel, $LegendaPainel, $TemaPainel);
		}
		else{
			$_SESSION['NomePainel'] = 'CSPainel';
			$_SESSION['LegendaPainel'] = $_TRA['gdp'];
			$_SESSION['LegendaPainel'] = 'theme-default';
			
			return array('CSPainel', $_TRA['gdp'], 'theme-default');
		}
	}
}

function EnviarEmail($Secure, $Host, $Port, $Username, $Password, $From, $Exibicao, $EmailDest, $Assunto, $Body, $AnexoLocal, $CopiaEmail = NULL, $AnexoLocal2 = NULL, $AnexoLocal3 = NULL){	
	require("plugin/phpmailer/class.phpmailer.php");
	require("plugin/phpmailer/class.smtp.php");
	
 	$mail = new PHPMailer();
	$mail->SetLanguage(Idioma(2), 'phpmailer/language/' );
 	
	$mail->IsSMTP();
	$mail->SMTPSecure = $Secure;
    $mail->Host = $Host;
    $mail->Port = $Port;
	$mail->SMTPAuth = true;
	$mail->Username = $Username;
	$mail->Password = $Password;
 
	//Remetente
	$mail->From = $From;
	$mail->Sender = $From;
	$mail->FromName = $Exibicao;
 
	//Destinatário
	$mail->AddAddress($EmailDest, $Assunto);
 	
	//Cópia de E-mail
	if(!empty($CopiaEmail)){
	$mail->AddBCC($CopiaEmail, $Assunto);
	}
	
	//Dados da Mensagem
	$mail->IsHTML(true);
	$mail->CharSet = "UTF-8";
 
	//Texto e Assunto
	$mail->Subject  = $Assunto;
	$mail->Body = $Body;
 
	//Anexo
	if(!empty($AnexoLocal)){
		$mail->AddAttachment($AnexoLocal, basename($AnexoLocal));
	}
	
	//Anexo 2
	if(!empty($AnexoLocal2)){
		$mail->AddAttachment($AnexoLocal2, basename($AnexoLocal2));
	}
	
	//Anexo 3
	if(!empty($AnexoLocal3)){
		$mail->AddAttachment($AnexoLocal3, basename($AnexoLocal3));
	}
 
	//Envia o e-mail
	$enviado = $mail->Send();
 
	//Limpa os destinatários e os anexos
	$mail->ClearAllRecipients();
	$mail->ClearAttachments();
	$mail->getSMTPInstance()->quit();
 
	// Exibe uma mensagem de resultado
	if ($enviado) {
		return 1;
	} else {
 		return $mail->ErrorInfo;
	}
}

function EnviarEmailCircular($Secure, $Host, $Port, $Username, $Password, $From, $Exibicao, $EmailDest, $Assunto, $Body){	
	require("plugin/phpmailer/class.phpmailer.php");
	require("plugin/phpmailer/class.smtp.php");
	
 	$mail = new PHPMailer();
	$mail->SetLanguage(Idioma(2), 'phpmailer/language/' );
 	
	$mail->IsSMTP();
	$mail->SMTPSecure = $Secure;
    $mail->Host = $Host;
    $mail->Port = $Port;
	$mail->SMTPAuth = true;
	$mail->Username = $Username;
	$mail->Password = $Password;
 
	//Remetente
	$mail->From = $From;
	$mail->Sender = $From;
	$mail->FromName = $Exibicao;
 
	//Destinatário
	$mail->AddAddress($EmailDest[0], $Assunto);
 	
	//Cópia de E-mail
	if(count($EmailDest) > 0){
		for($i=1; $i<count($EmailDest); $i++){
			$mail->AddBCC($EmailDest[$i], $Assunto);
		}
	}
		
	//Dados da Mensagem
	$mail->IsHTML(true);
	$mail->CharSet = "UTF-8";
 
	//Texto e Assunto
	$mail->Subject  = $Assunto;
	$mail->Body = $Body;
 
	//Envia o e-mail
	$enviado = $mail->Send();
 
	//Limpa os destinatários e os anexos
	$mail->ClearAllRecipients();
	$mail->ClearAttachments();
	$mail->getSMTPInstance()->quit();
 
	// Exibe uma mensagem de resultado
	if ($enviado) {
		return 1;
	} else {
 		return $mail->ErrorInfo;
	}
}

function DataSuporte($data){
	include_once(Idioma(1));
	global $_TRA;
	
	$hoje = date("j", time());
	$ontem = date("j", time() - (24*3600) ); 
	
	$dia = date("j", $data);
	$mes = date("n", $data);
	
	$hora = date("H", $data);
	$minuto = date("i", $data);
	
	if($mes == 1){
		$mesBr = $_TRA['jan'];
	}
	elseif($mes == 2){
		$mesBr = $_TRA['fev'];
	}
	elseif($mes == 3){
		$mesBr = $_TRA['mar'];
	}
	elseif($mes == 4){
		$mesBr = $_TRA['abr'];
	}
	elseif($mes == 5){
		$mesBr = $_TRA['maio'];
	}
	elseif($mes == 6){
		$mesBr = $_TRA['jun'];
	}
	elseif($mes == 7){
		$mesBr = $_TRA['jul'];
	}
	elseif($mes == 8){
		$mesBr = $_TRA['ago'];
	}
	elseif($mes == 9){
		$mesBr = $_TRA['set'];
	}
	elseif($mes == 10){
		$mesBr = $_TRA['out'];
	}
	elseif($mes == 11){
		$mesBr = $_TRA['nov'];
	}
	elseif($mes == 12){
		$mesBr = $_TRA['dez'];
	}
	
	if($dia == $hoje){
		$DataRetorno = $_TRA['Hoje'].", ".$hora.":".$minuto."";
	}
	elseif($dia == $ontem){
		$DataRetorno = $_TRA['Ontem'].", ".$hora.":".$minuto."";
	}
	else{
		$DataRetorno = $mesBr." ".date("d", $data);
	}
	
	return $DataRetorno;
}

function DataSuporte2($data){
	include_once(Idioma(1));
	global $_TRA;
	
	$hoje = date("j", time());
	$ontem = date("j", time() - (24*3600) ); 
	
	$dia = date("j", $data);
	$mes = date("n", $data);
	
	$hora = date("H", $data);
	$minuto = date("i", $data);
	
	if($mes == 1){
		$mesBr = $_TRA['jan'];
	}
	elseif($mes == 2){
		$mesBr = $_TRA['fev'];
	}
	elseif($mes == 3){
		$mesBr = $_TRA['mar'];
	}
	elseif($mes == 4){
		$mesBr = $_TRA['abr'];
	}
	elseif($mes == 5){
		$mesBr = $_TRA['maio'];
	}
	elseif($mes == 6){
		$mesBr = $_TRA['jun'];
	}
	elseif($mes == 7){
		$mesBr = $_TRA['jul'];
	}
	elseif($mes == 8){
		$mesBr = $_TRA['ago'];
	}
	elseif($mes == 9){
		$mesBr = $_TRA['set'];
	}
	elseif($mes == 10){
		$mesBr = $_TRA['out'];
	}
	elseif($mes == 11){
		$mesBr = $_TRA['nov'];
	}
	elseif($mes == 12){
		$mesBr = $_TRA['dez'];
	}
	
	if($dia == $hoje){
		$DataRetorno = $_TRA['Hoje'].", ".$mesBr." ".date("d", $data).", ".$hora.":".$minuto."";
	}
	elseif($dia == $ontem){
		$DataRetorno = $_TRA['Ontem'].", ".$mesBr." ".date("d", $data).", ".$hora.":".$minuto."";
	}
	else{
		$DataRetorno = $mesBr." ".date("d", $data).", ".$hora.":".$minuto;
	}
	
	return $DataRetorno;
}


function InfoConfigSuporte(){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	$CadUser = InfoUser(2);
	
	if( isset($_SESSION['SuportePaginacao']) ){
		return array(ceil($_SESSION['SuportePaginacao']));
	}
	else{
	
	$SQL = "SELECT SuportePaginacao FROM config_suporte WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
		if($Total > 0){
			$SQL->execute();
			$Ln = $SQL->fetch();
			
			$_SESSION['SuportePaginacao'] = ceil($Ln['SuportePaginacao']);
			return array(ceil($Ln['SuportePaginacao']));
			
		}
		else{
			$_SESSION['SuportePaginacao'] = 10;
			return array(10);
		}
	}
}

function ImagemAnexo($anexo){
	
	if( ($anexo == "zip") || ($anexo == "rar") ){
		$img = "<img src=\"img/filetree/zip.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "xls"){
		$img = "<img src=\"img/filetree/xls.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "txt"){
		$img = "<img src=\"img/filetree/txt.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "psd"){
		$img = "<img src=\"img/filetree/psd.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "ppt"){
		$img = "<img src=\"img/filetree/ppt.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif( ($anexo == "gif") || ($anexo == "png") || ($anexo == "jpg") || ($anexo == "jpeg") ){
		$img = "<img src=\"img/filetree/picture.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "php"){
		$img = "<img src=\"img/filetree/php.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "pdf"){
		$img = "<img src=\"img/filetree/pdf.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "mp3"){
		$img = "<img src=\"img/filetree/music.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif( ($anexo == "html") || ($anexo == "htm") ){
		$img = "<img src=\"img/filetree/html.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif( ($anexo == "doc") || ($anexo == "docm")){
		$img = "<img src=\"img/filetree/doc.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif( ($anexo == "db") || ($anexo == "sql") ){
		$img = "<img src=\"img/filetree/db.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	elseif($anexo == "css"){
		$img = "<img src=\"img/filetree/css.png\" width=\"16\" height=\"16\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"".$anexo."\" data-original-title=\"".$anexo."\"/>";
	}
	else{
		$img = "<span class=\"label label-primary\">".$anexo."</span>";
	}
	
	return $img;
}

function LimitarTexto($texto, $limite){
  $contador = strlen($texto);
  if ( $contador >= $limite ) {      
      $texto = substr($texto, 0, strrpos(substr($texto, 0, $limite), ' ')) . '';
      return $texto;
  }
  else{
    return $texto;
  }
} 

function ArvoreAdminExibir($usuario){	
	include("conexao.php");
	$Arvore = array();
		
	$SQL = "SELECT CadUser FROM admin WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
		while($LnSelect = $SQL->fetch()){
			if($LnSelect['CadUser'] != $usuario){
				$Arvore[] = $LnSelect['CadUser'];
				$SomarArvore = ArvoreAdminExibir($LnSelect['CadUser']);
				$Arvore = array_merge($Arvore, $SomarArvore);
			}
		}
	}
	
	return array_values(array_unique($Arvore));
}

function ArvoreExibir($User, $Arvore, $CadUser){	
	$exibirRev = "";	
	$VerArvore = array_reverse($Arvore);
	$VerArvore[] = $User;
	$ArvoreFinalTotal = count($VerArvore);
	for($i = 0; $i < $ArvoreFinalTotal; $i++){
		$exibirRev .= "[".$VerArvore[$i]."]";
		
		if($i != ($ArvoreFinalTotal - 1) ){
			$exibirRev .= " > ";
		}
	}
	
	$ret = explode("[".$CadUser."]", $exibirRev);
	$return = $CadUser.$ret[1];
	
	$return = str_replace("[","",$return);
	$return = str_replace("]","",$return);
	
	return $return;
}

function SelecionarArvore($CadUser){	
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$retornar = "<option value=\"".$CadUser."\">".$CadUser."</option>";
	
		$ArvoreAdmin = ArvoreAdmin($CadUser);
		for($i=0; $i<count($ArvoreAdmin); $i++){
			$ArvoreAdminExibir = ArvoreAdminExibir($ArvoreAdmin[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreAdmin[$i], $ArvoreAdminExibir, $CadUser);
			$retornar .= "<option value=\"".$ArvoreAdmin[$i]."\">".$ArvoreExibir."</option>";
		}
	return $retornar;
}

function SelecionarExibirAdmin($CadUser){	
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$retornar = "<li><a usuario=\"".$CadUser."\" class=\"Exibir pointer\">".$CadUser."</a></li>";
	
		$ArvoreAdmin = ArvoreAdmin($CadUser);
		for($i=0; $i<count($ArvoreAdmin); $i++){
			$ArvoreAdminExibir = ArvoreAdminExibir($ArvoreAdmin[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreAdmin[$i], $ArvoreAdminExibir, $CadUser);
			$retornar .= "<li><a usuario=\"".$ArvoreAdmin[$i]."\" class=\"Exibir pointer\">".$ArvoreExibir."</a></li>";
		}
	return $retornar;
}

function SelecionarExibir($CadUser){	
	include("conexao.php");
	
	$retornar = "";
	
		$ArvoreAdmin = ArvoreAdmin($CadUser);
		for($i=0; $i<count($ArvoreAdmin); $i++){
			$ArvoreAdminExibir = ArvoreAdminExibir($ArvoreAdmin[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreAdmin[$i], $ArvoreAdminExibir, $CadUser);
			$retornar .= "<li><a usuario=\"".$ArvoreAdmin[$i]."\" class=\"Exibir pointer\">".$ArvoreExibir."</a></li>";
		}
	return $retornar;
}

function SelecionarArvoreAll($CadUser){
	$retornar = "<option value=\"".$CadUser."\">".$CadUser."</option>";
	
	$retornar .= SelecionarArvoreAdmin($CadUser);
	$retornar .= SelecionarArvoreRev($CadUser);
	
	return $retornar;
}

function SelecionarArvoreAdmin($CadUser){	
	include("conexao.php");
	
	$retornar = "";
	
		$ArvoreAdmin = ArvoreAdmin($CadUser);
		for($i=0; $i<count($ArvoreAdmin); $i++){
			$ArvoreAdminExibir = ArvoreAdminExibir($ArvoreAdmin[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreAdmin[$i], $ArvoreAdminExibir, $CadUser);
			$retornar .= "<option value=\"".$ArvoreAdmin[$i]."\">".$ArvoreExibir."</option>";
		}
	return $retornar;
}

function ArvoreRevExibir($usuario){	
	include("conexao.php");
	$Arvore = array();
		
	$SQL = "SELECT CadUser FROM rev WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
		while($LnSelect = $SQL->fetch()){
			if($LnSelect['CadUser'] != $usuario){
				$Arvore[] = $LnSelect['CadUser'];
				$SomarArvore = ArvoreRevExibir($LnSelect['CadUser']);
				$Arvore = array_merge($Arvore, $SomarArvore);
			}
		}
	}
	
	return array_values(array_unique($Arvore));
}

function SelecionarArvoreRev($CadUser){	
	include("conexao.php");
	$retornar = "";
	
		$ArvoreRev = ArvoreRev($CadUser);
		for($i=0; $i<count($ArvoreRev); $i++){
			$ArvoreRevExibir = ArvoreRevExibir($ArvoreRev[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreRev[$i], $ArvoreRevExibir, $CadUser);
			$retornar .= "<option value=\"".$ArvoreRev[$i]."\">".$ArvoreExibir."</option>";
		}

	return $retornar;
}

function SelecionarServerBackup($server){	
	include("conexao.php");
	$retornar = "";
	$Somatorio = 0;
	
	$SQLServer = "SELECT * FROM server WHERE id = :id";
	$SQLServer = $painel_geral->prepare($SQLServer);
	$SQLServer->bindParam(':id', $server, PDO::PARAM_STR);
	$SQLServer->execute();
	$TotalServer = $SQLServer->fetch();
	
	if($TotalServer > 0){
		$Somatorio += 1;
		$SQLServer->execute();
		$LnServer = $SQLServer->fetch();
		$retornar .= "<option value=\"".$LnServer['id']."\">".$LnServer['nome']."</option>";
	}
	
	$SQLServer = "SELECT * FROM server WHERE id != :id";
	$SQLServer = $painel_geral->prepare($SQLServer);
	$SQLServer->bindParam(':id', $server, PDO::PARAM_STR);
	$SQLServer->execute();
	$TotalServer = $SQLServer->fetch();
	
	if($TotalServer > 0){
		$Somatorio += 1;
		$SQLServer->execute();
		while($LnServer = $SQLServer->fetch()){
			$retornar .= "<option value=\"".$LnServer['id']."\">".$LnServer['nome']."</option>";
		}
	}
	
	if($Somatorio == 0) return "<option value=\"0\">Configure um Servidor</option>";
	
	return $retornar;
}

function SelecionarExibirAll($CadUser){
	include_once(Idioma(1));
	global $_TRA;
	
	$retornar = " <li><a usuario=\"Todos\" class=\"Exibir pointer\">".$_TRA['Todos']."</a></li>";
	$retornar .= "<li><a usuario=\"".$CadUser."\" class=\"Exibir pointer\">".$CadUser."</a></li>";
	
	$retornar .= SelecionarExibir($CadUser);
    $retornar .= SelecionarExibirRev($CadUser);
	
	return $retornar;
}

function SelecionarExibirRev($CadUser){	
	include("conexao.php");
	$retornar = "";
	
		$ArvoreRev = ArvoreRev($CadUser);
		for($i=0; $i<count($ArvoreRev); $i++){
			$ArvoreRevExibir = ArvoreRevExibir($ArvoreRev[$i]);
			$ArvoreExibir = ArvoreExibir($ArvoreRev[$i], $ArvoreRevExibir, $CadUser);
			$retornar .= "<li><a usuario=\"".$ArvoreRev[$i]."\" class=\"Exibir pointer\">".$ArvoreExibir."</a></li>";
		}

	return $retornar;
}

function ConvertDataPremium($data){
	include_once(Idioma(1));
	global $_TRA;
	
	$DataAtual = time();										
	$FaltaDias = $data - $DataAtual;
	$dias_restantes = ceil($FaltaDias / 60 / 60 / 24);
	$DataExpirar = date('d/m/Y', $data);
	
	$DiasSS = $dias_restantes > 1 ? "dias" : "dia";
	
	if($dias_restantes == 0){
		$return = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Hoje']." (".$DataExpirar.")\">".$_TRA['Hoje']." (".$DataExpirar.")</span>";	
	}
	elseif($dias_restantes < 1){
		$return = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Esgotado']." (".$DataExpirar.")\">".$_TRA['Esgotado']." (".$DataExpirar.")</span>";	
	}
	elseif($dias_restantes < 4){
		$return = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$dias_restantes." ".$DiasSS." (".$DataExpirar.")\">".$dias_restantes." ".$DiasSS." (".$DataExpirar.")</span>";	
	}
	else{
		$return = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$dias_restantes." ".$DiasSS." (".$DataExpirar.")\">".$dias_restantes." ".$DiasSS." (".$DataExpirar.")</span>";	
	}
	return $return;
}

function ConvertDataPremiumMenu($data, $prepago = NULL){
	include_once(Idioma(1));
	global $_TRA;
	
	if($data == "Admin"){
		return "<span class=\"pointer btn btn-danger\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$_TRA['admin']."\">".$_TRA['admin']."</span>";
	}
	
	if($prepago == "S"){
		$CotaDias = $_SESSION['CotaDias'];
		$CotasDiasSS = $CotaDias > 1 ? $_TRA['dias'] : $_TRA['dia'];
		$cotas_restantes = $_SESSION['Cota'];
		$CotasSS = $cotas_restantes > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
		
		if($cotas_restantes > 0){
			return "<span class=\"pointer btn btn-info\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$cotas_restantes." ".$CotasSS." (".$CotaDias." ".$CotasDiasSS.")\">".$cotas_restantes." ".$CotasSS."</span>";
		}
		else{
			return "<span class=\"pointer btn btn-danger\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$cotas_restantes." ".$CotasSS." (".$CotaDias." ".$CotasDiasSS.")\">".$cotas_restantes." ".$CotasSS."</span>";
		}
	}
	
	$DataAtual = time();										
	$FaltaDias = $data - $DataAtual;
	$dias_restantes = ceil($FaltaDias / 60 / 60 / 24);
	$DataExpirar = date('d/m/Y', $data);
	
	$DiasSS = $dias_restantes > 1 ? $_TRA['dias'] : $_TRA['dia'];
	
	if($dias_restantes == 0){
		$return = "<span class=\"pointer btn btn-warning\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$_TRA['Hoje']." (".$DataExpirar.")\">".$_TRA['Hoje']."</span>";	
	}
	elseif($dias_restantes < 1){
		$return = "<span class=\"pointer btn btn-danger\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$_TRA['Esgotado']." (".$DataExpirar.")\">".$_TRA['Esgotado']."</span>";	
	}
	elseif($dias_restantes < 4){
		$return = "<span class=\"pointer btn btn-warning\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$dias_restantes." ".$DiasSS." (".$DataExpirar.")\">".$dias_restantes." ".$DiasSS."</span>";	
	}
	else{
		$return = "<span class=\"pointer btn btn-success\" data-toggle=\"tooltip\" data-placement=\"bottom\" title=\"\" data-original-title=\"".$dias_restantes." ".$DiasSS." (".$DataExpirar.")\">".$dias_restantes." ".$DiasSS."</span>";	
	}
	return $return;
}

function ConverterDinheiro($valor){
	$data = str_replace("R$","",$valor);
	$data = str_replace("€","",$data);
	$data = str_replace("US$","",$data);
	$data = str_replace(",",".",$data);
	$data = str_replace(" ",".",trim($data));
	return trim($data);
}

function VerificarEmailUser($CadUser, $coluna){
	include("conexao.php");
	
	$SQL = "SELECT id FROM email_adicionar WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	$bloqueado = "N";
	$SQLBlo = "SELECT id FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLBlo = $painel_geral->prepare($SQLBlo);
	$SQLBlo->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBlo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLBlo->execute();
	$TotalBlo = count($SQLBlo->fetchAll());
	
	$SQLMod = "SELECT id FROM email_modelo WHERE CadUser = :CadUser";
	$SQLMod = $painel_geral->prepare($SQLMod);
	$SQLMod->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLMod->execute();
	$LnMod = $SQLMod->fetch();
	
	$SQLPre = "SELECT ".$coluna." FROM email_preferencias WHERE CadUser = :CadUser";
	$SQLPre = $painel_geral->prepare($SQLPre);
	$SQLPre->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPre->execute();
	$LnPre = $SQLPre->fetch();
	
	$SQLPreVer = "SELECT bloqueado FROM email_modelo WHERE CadUser = :CadUser AND id = :id";
	$SQLPreVer = $painel_geral->prepare($SQLPreVer);
	$SQLPreVer->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPreVer->bindParam(':id', $LnPre[$coluna], PDO::PARAM_INT);
	$SQLPreVer->execute();
	$LnPreVer = $SQLPreVer->fetch();
	
	if(empty($Ln)){
		return 1;
	}
	elseif($TotalBlo == 0){
		return 2;
	}
	elseif(empty($LnMod)){
		return 3;
	}
	elseif(empty($LnPre)){
		return 4;
	}
	elseif(empty($LnPreVer)){
		return 5;
	}
	elseif($LnPreVer['bloqueado'] == "S"){
		return 6;
	}
	else{
		return false;
	}
	
}

function SelecionarModelo($CadUser, $coluna, $LoginCli, $SenhaCli, $NomeCli, $VcCli, $Perfil){
	include("conexao.php");
	
	$NomePerfil = "";
	$UrlPerfil = "";
	$PortaPerfil = "";
	$TotalPerfil = count($Perfil);
	for($i=0; $i < $TotalPerfil; $i++){
		
		$bloqueado = "N";
		$SQLPerfil = "SELECT id, url, nome, porta, valorcsp FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
		$SQLPerfil = $painel_geral->prepare($SQLPerfil);
		$SQLPerfil->bindParam(':valorcsp', $Perfil[$i], PDO::PARAM_STR); 
		$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
		$SQLPerfil->execute();
		
		while($LnPerfil = $SQLPerfil->fetch()){
			
		//Verificar se existe máscara com o valor do CSP
		$UrlPerfilMask = $LnPerfil['url'];
		$UrlNomeMask = $LnPerfil['nome'];
		$UrlPortaMask = $LnPerfil['porta'];
											
		$bloqueado = "N";
		$SQLM = "SELECT id FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
		$SQLM = $painel_geral->prepare($SQLM);
		$SQLM->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
		$SQLM->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
		$SQLM->execute();
												
		$idperfil = "";
		while($LnM = $SQLM->fetch()){
			$idperfil .= $LnM['id'].",";
		}
		$idperfil = substr($idperfil, -0, -1);
														
		$SQLMk = "SELECT id FROM mascaraurl WHERE FIND_IN_SET(perfil,:perfil) AND bloqueado = :bloqueado AND CadUser = :CadUser";
		$SQLMk = $painel_geral->prepare($SQLMk);
		$SQLMk->bindParam(':perfil', $idperfil, PDO::PARAM_STR);
		$SQLMk->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
		$SQLMk->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQLMk->execute();
		$TotalMk = count($SQLMk->fetchAll());
		//Exit
				
		$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
		$nome = $MaskPerfil[0];
		$url = $MaskPerfil[1];
		$porta = $MaskPerfil[2];
		
		if( ($UrlPerfilMask == $url) && ($UrlNomeMask == $nome) && ($UrlPortaMask == $porta) && ($TotalMk > 0) ){
			continue;
		}

		$NomePerfil .= $nome;
		$NomePerfil .= " ";
		
		$UrlPerfil .= $nome.": ".$url;
		$UrlPerfil .= "<br>";
		
		$PortaPerfil .= $nome.": ".$porta;
		$PortaPerfil .= "<br>";
		
		}
	}
	
	$SQLDeskey = "SELECT deskeys FROM painel_config";
	$SQLDeskey = $painel_geral->prepare($SQLDeskey);
	$SQLDeskey->execute();
	$LnDeskey = $SQLDeskey->fetch();
	
	$SQLInfo = "SELECT NomePainel FROM site_config";
	$SQLInfo = $painel_geral->prepare($SQLInfo);
	$SQLInfo->execute();
	$LnInfo = $SQLInfo->fetch();

	$NomePainel = empty($LnInfo['NomePainel']) ? 'CSPainel' : $LnInfo['NomePainel'];
	$deskeys = empty($LnDeskey['deskeys']) ? '0102030405060708091011121314' : $LnDeskey['deskeys'];
	
	$SQLPre = "SELECT ".$coluna." FROM email_preferencias WHERE CadUser = :CadUser";
	$SQLPre = $painel_geral->prepare($SQLPre);
	$SQLPre->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPre->execute();
	$LnPre = $SQLPre->fetch();
	
	$SQLPreVer = "SELECT assunto, mensagem FROM email_modelo WHERE CadUser = :CadUser AND id = :id";
	$SQLPreVer = $painel_geral->prepare($SQLPreVer);
	$SQLPreVer->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPreVer->bindParam(':id', $LnPre[$coluna], PDO::PARAM_INT);
	$SQLPreVer->execute();
	$LnPreVer = $SQLPreVer->fetch();
	
	//Informações do Usuário Emissor
	$SQLUser = "SELECT nome, email FROM admin WHERE usuario = :usuario UNION SELECT nome, email FROM rev WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$NomeEmissor = empty($LnUser['nome']) ? $CadUser : $LnUser['nome'];
	$EmailEmissor = empty($LnUser['email']) ? '' : $LnUser['email'];
	
	$NomeCliente = empty($NomeCli) ? $LoginCli : $NomeCli;
	
	$NomePerfil = str_replace(" ",", ",trim($NomePerfil)).".";
	
	$mensagem = $LnPreVer['mensagem'];
	$mensagem = str_replace("[MEUEMAIL]",$EmailEmissor,$mensagem);
	$mensagem = str_replace("[MEUNOME]",$NomeEmissor,$mensagem);
	$mensagem = str_replace("[LGCLIENTE]",$LoginCli,$mensagem);
	$mensagem = str_replace("[SNCLIENTE]",$SenhaCli,$mensagem);
	$mensagem = str_replace("[NMCLIENTE]",$NomeCliente,$mensagem);
	$mensagem = str_replace("[VCCLIENTE]",$VcCli,$mensagem);
	$mensagem = str_replace("[NOMEPERFIL]",$NomePerfil,$mensagem);
	$mensagem = str_replace("[URLPERFIL]",$UrlPerfil,$mensagem);
	$mensagem = str_replace("[PORTAPERFIL]",$PortaPerfil,$mensagem);
	$mensagem = str_replace("[DESKEYS]",$deskeys,$mensagem);
	$mensagem = str_replace("[URLPAINEL]",UrlAtual(),$mensagem);
	$mensagem = str_replace("[NOMEPAINEL]",$NomePainel,$mensagem);
	
	return array($LnPreVer['assunto'], $mensagem);
	
}

function VerificarSMSUser($CadUser, $coluna){
	include("conexao.php");
	
	$SQL = "SELECT id FROM sms WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	$bloqueado = "N";
	$SQLBlo = "SELECT id FROM sms WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLBlo = $painel_geral->prepare($SQLBlo);
	$SQLBlo->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBlo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLBlo->execute();
	$TotalBlo = count($SQLBlo->fetchAll());
	
	$SQLMod = "SELECT id FROM sms_modelo WHERE CadUser = :CadUser";
	$SQLMod = $painel_geral->prepare($SQLMod);
	$SQLMod->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLMod->execute();
	$LnMod = $SQLMod->fetch();
	
	$SQLPre = "SELECT ".$coluna." FROM sms_preferencias WHERE CadUser = :CadUser";
	$SQLPre = $painel_geral->prepare($SQLPre);
	$SQLPre->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPre->execute();
	$LnPre = $SQLPre->fetch();
	
	$SQLPreVer = "SELECT bloqueado FROM sms_modelo WHERE CadUser = :CadUser AND id = :id";
	$SQLPreVer = $painel_geral->prepare($SQLPreVer);
	$SQLPreVer->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPreVer->bindParam(':id', $LnPre[$coluna], PDO::PARAM_INT);
	$SQLPreVer->execute();
	$LnPreVer = $SQLPreVer->fetch();
	
	if(empty($Ln)){
		return 1;
	}
	elseif($TotalBlo == 0){
		return 2;
	}
	elseif(empty($LnMod)){
		return 3;
	}
	elseif(empty($LnPre)){
		return 4;
	}
	elseif(empty($LnPreVer)){
		return 5;
	}
	elseif($LnPreVer['bloqueado'] == "S"){
		return 6;
	}
	else{
		return false;
	}
	
}

function VerificarSMSLibComputador($CadUser){
	include("conexao.php");
	
	$SQL = "SELECT id FROM sms WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	$bloqueado = "N";
	$SQLBlo = "SELECT id FROM sms WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLBlo = $painel_geral->prepare($SQLBlo);
	$SQLBlo->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBlo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLBlo->execute();
	$TotalBlo = count($SQLBlo->fetchAll());
	
	if(empty($Ln)){
		return 1;
	}
	elseif($TotalBlo == 0){
		return 2;
	}
	else{
		return false;
	}
	
}

function cut_str($str, $left, $right){
		$str = substr(stristr($str, $left) , strlen($left));
		$leftLen = strlen(stristr($str, $right));
		$leftLen = $leftLen ? -($leftLen) : strlen($str);
		$str = substr($str, 0, $leftLen);
		return $str;
	}

function EnviarSMS($CadUser, $mensagem, $celular){
	include("conexao.php");
	date_default_timezone_set('America/Sao_Paulo');

	$time = time();
	
	//Seleciona o servidor
	$bloqueado = "N";
	$SQLSMS = "SELECT user, senha, creditos, valor FROM sms WHERE CadUser = :CadUser AND bloqueado = :bloqueado AND creditos > 0";
	$SQLSMS = $painel_geral->prepare($SQLSMS);
	$SQLSMS->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLSMS->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLSMS->execute();
	$LnSMS = $SQLSMS->fetch();

	#$usuario = $LnSMS['user'];	
	#$senha = $LnSMS['senha'];
	$deviceID = $LnSMS['user'];	
	$secret = $LnSMS['senha'];
	$credito = $LnSMS['creditos'];
	$valor = $LnSMS['valor'];
		
	$celular = LimparCelular($celular);
	$celular = "55".$celular;
	
	$mensagem = str_replace("<br>","; ",$mensagem);
	$mensagem = str_replace("<br />","; ",$mensagem);
	$mensagem = str_replace("<br/>","; ",$mensagem);
		
	#$url2 = "http://torpedus.com.br/sms/index.php?app=webservices&u=".urlencode($usuario)."&p=".urlencode($senha)."&ta=pv&to=".urlencode($celular)."&msg=".urlencode($mensagem)."";
	
	$url = "http://gerencia.xevolution.pro/gatewaysms/?to=".urlencode($celular)."&text=".urlencode($mensagem)."&secret=$secret&time=$time&deviceID=".urlencode($deviceID)."";
	
	$curl = curl_init($url);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $msg = curl_exec($curl);
	$respArray = json_decode($msg, true);
	$status = $respArray['success'];
	curl_close($curl);
		
	if($status == 1){		
		$total = $credito - $valor;
		$SQL = "UPDATE sms SET creditos = '".$total."' WHERE CadUser = '".$CadUser."'";
		$SQL = $painel_geral->prepare($SQL); 
		$SQL->execute();
		return 1;
	}else{
		return 2;
	}
	
}

function SelecionarModeloSMS($CadUser, $coluna, $LoginCli, $SenhaCli, $NomeCli, $VcCli, $Perfil){
	include("conexao.php");
	
	$NomePerfil = "";
	$UrlPerfil = "";
	$PortaPerfil = "";
	$TotalPerfil = count($Perfil);
	for($i=0; $i < $TotalPerfil; $i++){
		
		$bloqueado = "N";
		$SQLPerfil = "SELECT id, url, nome, porta, valorcsp FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
		$SQLPerfil = $painel_geral->prepare($SQLPerfil);
		$SQLPerfil->bindParam(':valorcsp', $Perfil[$i], PDO::PARAM_STR); 
		$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
		$SQLPerfil->execute();
		
		while($LnPerfil = $SQLPerfil->fetch()){
		
		//Verificar se existe máscara com o valor do CSP
		$UrlPerfilMask = $LnPerfil['url'];
		$UrlNomeMask = $LnPerfil['nome'];
		$UrlPortaMask = $LnPerfil['porta'];
											
		$bloqueado = "N";
		$SQLM = "SELECT id FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
		$SQLM = $painel_geral->prepare($SQLM);
		$SQLM->bindParam(':valorcsp', $LnPerfil['valorcsp'], PDO::PARAM_STR);
		$SQLM->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
		$SQLM->execute();
												
		$idperfil = "";
		while($LnM = $SQLM->fetch()){
			$idperfil .= $LnM['id'].",";
		}
		$idperfil = substr($idperfil, -0, -1);
														
		$SQLMk = "SELECT id FROM mascaraurl WHERE FIND_IN_SET(perfil,:perfil) AND bloqueado = :bloqueado AND CadUser = :CadUser";
		$SQLMk = $painel_geral->prepare($SQLMk);
		$SQLMk->bindParam(':perfil', $idperfil, PDO::PARAM_STR);
		$SQLMk->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
		$SQLMk->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
		$SQLMk->execute();
		$TotalMk = count($SQLMk->fetchAll());
		//Exit
				
		$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
		$nome = $MaskPerfil[0];
		$url = $MaskPerfil[1];
		$porta = $MaskPerfil[2];
		
		if( ($UrlPerfilMask == $url) && ($UrlNomeMask == $nome) && ($UrlPortaMask == $porta) && ($TotalMk > 0) ){
			continue;
		}

		$NomePerfil .= $nome;
		$NomePerfil .= " ";
		
		$UrlPerfil .= $nome.": ".$url;
		$UrlPerfil .= "<br>";
		
		$PortaPerfil .= $nome.": ".$porta;
		$PortaPerfil .= "<br>";
		
		}
	}
	
	$SQLDeskey = "SELECT deskeys FROM painel_config";
	$SQLDeskey = $painel_geral->prepare($SQLDeskey);
	$SQLDeskey->execute();
	$LnDeskey = $SQLDeskey->fetch();
	
	$SQLInfo = "SELECT NomePainel FROM site_config";
	$SQLInfo = $painel_geral->prepare($SQLInfo);
	$SQLInfo->execute();
	$LnInfo = $SQLInfo->fetch();

	$NomePainel = empty($LnInfo['NomePainel']) ? 'CSPainel' : $LnInfo['NomePainel'];
	$deskeys = empty($LnDeskey['deskeys']) ? '0102030405060708091011121314' : $LnDeskey['deskeys'];
	
	$SQLPre = "SELECT ".$coluna." FROM sms_preferencias WHERE CadUser = :CadUser";
	$SQLPre = $painel_geral->prepare($SQLPre);
	$SQLPre->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPre->execute();
	$LnPre = $SQLPre->fetch();
	
	$SQLPreVer = "SELECT assunto, mensagem FROM sms_modelo WHERE CadUser = :CadUser AND id = :id";
	$SQLPreVer = $painel_geral->prepare($SQLPreVer);
	$SQLPreVer->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPreVer->bindParam(':id', $LnPre[$coluna], PDO::PARAM_INT);
	$SQLPreVer->execute();
	$LnPreVer = $SQLPreVer->fetch();
	
	//Informações do Usuário Emissor
	$SQLUser = "SELECT nome, email FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$NomeEmissor = empty($LnUser['nome']) ? $CadUser : $LnUser['nome'];
	$EmailEmissor = empty($LnUser['email']) ? '' : $LnUser['email'];
	
	$NomeCliente = empty($NomeCli) ? $LoginCli : $NomeCli;
	
	$NomePerfil = str_replace(" ",", ",trim($NomePerfil)).".";
	
	$mensagem = $LnPreVer['mensagem'];
	$mensagem = str_replace("[MEUEMAIL]",$EmailEmissor,$mensagem);
	$mensagem = str_replace("[MEUNOME]",$NomeEmissor,$mensagem);
	$mensagem = str_replace("[LGCLIENTE]",$LoginCli,$mensagem);
	$mensagem = str_replace("[SNCLIENTE]",$SenhaCli,$mensagem);
	$mensagem = str_replace("[NMCLIENTE]",$NomeCliente,$mensagem);
	$mensagem = str_replace("[VCCLIENTE]",$VcCli,$mensagem);
	$mensagem = str_replace("[NOMEPERFIL]",$NomePerfil,$mensagem);
	$mensagem = str_replace("[URLPERFIL]",$UrlPerfil,$mensagem);
	$mensagem = str_replace("[PORTAPERFIL]",$PortaPerfil,$mensagem);
	$mensagem = str_replace("[DESKEYS]",$deskeys,$mensagem);
	$mensagem = str_replace("[URLPAINEL]",UrlAtual(),$mensagem);
	$mensagem = str_replace("[NOMEPAINEL]",$NomePainel,$mensagem);
	
	return $mensagem;
	
}

function VerificarVerEmail($CadUser){
	include("conexao.php");
	
	$SQL = "SELECT id FROM email_adicionar WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$TotalEmail = count($SQL->fetchAll());
	
	$bloqueado = "S";
	$SQLBlo = "SELECT id FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLBlo = $painel_geral->prepare($SQLBlo);
	$SQLBlo->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBlo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLBlo->execute();
	$TotalBlo = count($SQLBlo->fetchAll());
	
	if($TotalEmail == 0){
		return 1;
	}
	elseif( ($TotalBlo == $TotalEmail) ){
		return 2;
	}
	else{
		return false;
	}
	
}

function VerificarTempoTesteEditar($id){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$return = "";
	
	$bloqueado = "N";
	$SQLS = "SELECT id, tempo FROM tempoteste WHERE id = :id AND bloqueado = :bloqueado ORDER by tempo ASC";
	$SQLS = $painel_geral->prepare($SQLS);
	$SQLS->bindParam(':id', $id, PDO::PARAM_INT);
	$SQLS->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLS->execute();
	$LnS = $SQLS->fetch();
	$StempoS = $LnS['tempo'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
	
	if(!empty($LnS)) $return .= "<option value=\"".$LnS['id']."\">".$LnS['tempo']." ".$StempoS."</option>";
	
	$SQL = "SELECT id, tempo FROM tempoteste WHERE id != :id AND bloqueado = :bloqueado ORDER by tempo ASC";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $id, PDO::PARAM_INT);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	
	while($Ln = $SQL->fetch()){
		$Stempo = $Ln['tempo'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
		$return .= "<option value=\"".$Ln['id']."\">".$Ln['tempo']." ".$Stempo."</option>";
	}
	
	if(empty($return)) $return = "<option value=\"0\">".$_TRA['nettd']."</option>";
	
	return $return;
	
	
}

function VerificarTempoTeste(){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$return = "";
	
	$bloqueado = "N";
	$SQL = "SELECT id, tempo FROM tempoteste WHERE bloqueado = :bloqueado ORDER by tempo ASC";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	
	while($Ln = $SQL->fetch()){
		$Stempo = $Ln['tempo'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
		$return .= "<option value=\"".$Ln['id']."\">".$Ln['tempo']." ".$Stempo."</option>";
	}
	
	if(empty($return)) $return = "<option value=\"0\">".$_TRA['nettd']."</option>";
	
	return $return;
	
	
}

function ContarUsuarioTotal($UserOnline){
	include("conexao.php");	
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$ativo = 0;
	$esgotado = 0;
	$bloqueado = 0;
		
	$SQLUser = "SELECT bloqueado, data_premio, conexao FROM usuario WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();

	$DataAtual = strtotime(date('Y-m-d'));
	while($LnUser = $SQLUser->fetch()){
		if( ($LnUser['bloqueado'] == "N") && ($LnUser['data_premio'] >= $DataAtual) ){
			$ativo += 1;
		}
		elseif( ($LnUser['data_premio'] < $DataAtual) ){
			$esgotado += 1;
		}
		elseif( ($LnUser['bloqueado'] == "S") ){
			$bloqueado += 1;
		}
	}
	
	return array($ativo, $esgotado, $bloqueado);
}


function AtivoTotalRev($UserOnline){
	include("conexao.php");	
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$bloqueado = "N";
	$DataAtual = strtotime(date('Y-m-d'));
	
	$SQLUser = "SELECT id FROM usuario WHERE FIND_IN_SET(CadUser,:CadUser) AND bloqueado = :bloqueado AND data_premio >= :data_premio";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLUser->bindParam(':data_premio', $DataAtual, PDO::PARAM_STR);
	$SQLUser->execute();
	$Total = count($SQLUser->fetchAll());	
	
	return $Total;
}

function ContarUsuarioRelatorio($UserOnline, $tipo){
	include("conexao.php");	
	$VerTotalUser = array();
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$ativoSAT = 0;
	$ativoCSAT = 0;
	$ativoCAB = 0;
	$ativoCCAB = 0;
	$TotalUser = 0;
	
	if($tipo == "T"){
		$TabPerfil = "FIND_IN_SET(CadUser,:CadUser)";
	}
	else{
	$ArrayPerfil = array();
	$SQLPerfil = "SELECT valorcsp FROM perfil WHERE tipo = :tipo";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQLPerfil->execute();
	while($LnPerfil = $SQLPerfil->fetch()){
		if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
			$ArrayPerfil[] = "FIND_IN_SET(CadUser,:CadUser) AND perfil LIKE '%".$LnPerfil['valorcsp']."%'";
		}
	}
		$TabPerfil = implode(' OR ', $ArrayPerfil);
	}
				
	$SQLUser = "SELECT usuario, bloqueado, data_premio, conexao, perfil FROM usuario WHERE ".$TabPerfil;
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	
	$DataAtual = strtotime(date('Y-m-d'));
	while($LnUser = $SQLUser->fetch()){
		
		if(!in_array($LnUser['usuario'], $VerTotalUser)) {
			$VerTotalUser[] = $LnUser['usuario'];
			$TotalUser += 1;
		}

		$perfil = str_replace("][","],[",$LnUser['perfil']);
		
		$SQLP = "SELECT tipo FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp)";
		$SQLP = $painel_geral->prepare($SQLP);
		$SQLP->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
		$SQLP->execute();
		
		$ArrayOperadora = array();
		while($LnP = $SQLP->fetch()){
			$tipoP = $LnP['tipo'];
			
			if(!in_array($tipoP, $ArrayOperadora)) {
				$ArrayOperadora[] = $tipoP;
				if($tipoP == "SAT"){
					if( ($LnUser['bloqueado'] == "N") && ($LnUser['data_premio'] >= $DataAtual) ){
						$ativoSAT += 1;
						$ativoCSAT += $LnUser['conexao'];
					}
				}
				else{
					if( ($LnUser['bloqueado'] == "N") && ($LnUser['data_premio'] >= $DataAtual) ){
						$ativoCAB += 1;
						$ativoCCAB += $LnUser['conexao'];
					}
				}
			}
		}		
	}
	
	return array($ativoSAT, $ativoCSAT, $ativoCAB, $ativoCCAB, $TotalUser);
}

function ContarTesteAtivo($UserOnline){
	include("conexao.php");	
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$DataAtual = strtotime(date('Y-m-d'));
	$bloqueado = "N";
	$SQLUser = "SELECT id FROM teste WHERE FIND_IN_SET(CadUser,:CadUser) AND bloqueado = :bloqueado AND data_premio >= :data_premio";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLUser->bindParam(':data_premio', $DataAtual, PDO::PARAM_STR);
	$SQLUser->execute();
	
	$TotalUser = count($SQLUser->fetchAll());
	
	return $TotalUser;
}

function ValorPerfil($perfil){
	$perfil = str_replace("[","",$perfil);
	$perfil = str_replace("]","",$perfil);
	return $perfil;
}

function FormatoData($data){
	
	if(substr_count($data, "-") == 0){
		return 1;
	}
	
	if(substr_count($data, " ") > 0){
		$d = explode(" ",$data);
		$data = $d[0];
	}
	
	$ex = explode("-",$data);
	if( (strlen($ex[0]) != 4) || (strlen($ex[1]) != 2) || (strlen($ex[2]) != 2) ){
		return 1;
	}
	
	return $data;
	
}

function ConverterPerfil($perfil){
	
	$perfil = trim($perfil);
	
	if(substr_count($perfil, " ") > 0){
		$perfil = str_replace(" ","][",$perfil);
		$perfil = "[".$perfil."]";
	}
	else{
		$perfil = "[".$perfil."]";
	}
	
	return $perfil;
}

function UrlTeste($acao, $code = NULL){
	if($acao == 1){
		$CadUser = InfoUser(2);
		$url = UrlAtual()."cadtest.php?r=".base64_encode(base64_encode(base64_encode(base64_encode($CadUser))));
	}
	elseif($acao == 2){
		$url = base64_decode(base64_decode(base64_decode(base64_decode($code))));
	}
	
	return trim($url);
	
}

function VerTeste($CadUser){
	include("conexao.php");	
	$status = 0;
	
	$SQLUrlT = "SELECT status, tempo, cemail, email FROM urlteste WHERE CadUser = :CadUser";
	$SQLUrlT = $painel_geral->prepare($SQLUrlT);
	$SQLUrlT->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUrlT->execute();
	$LnUrlT = $SQLUrlT->fetch();
	$tempo = empty($LnUrlT['tempo']) ? 0 : $LnUrlT['tempo'];
	$cemail = empty($LnUrlT['cemail']) ? "N" : $LnUrlT['cemail'];
	$email = empty($LnUrlT['email']) ? "" : $LnUrlT['email'];
	
	if(empty($LnUrlT)){
		$status = 0;
	}
	elseif($LnUrlT['status'] == "S"){
		$status = 1;
	}
	else{
		$status = 0;
	}
	
	
	return array($status, $tempo, $cemail, $email);
}

function SelectOperadora($CadUser){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
		
	$SQLCad = "SELECT perfil FROM admin WHERE usuario = :usuario UNION SELECT perfil FROM rev WHERE usuario = :usuario";
	$SQLCad = $painel_user->prepare($SQLCad);
	$SQLCad->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLCad->execute();
	$LnCad = $SQLCad->fetch();
		
	$bloqueado = "N";
	$Perfil = "";
	
	$SQLPerfil = "SELECT id, nome, valorcsp FROM perfil WHERE bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
		
		$ArrayPerfil = array();
		while($LnPerfil = $SQLPerfil->fetch()){
			if(substr_count($LnCad['perfil'], $LnPerfil['valorcsp']) > 0) {
				if(!in_array($LnPerfil['valorcsp'], $ArrayPerfil)) {
				$MaskPerfil = MaskPerfil($CadUser, $LnPerfil['id']);
				$ArrayPerfil[] = $LnPerfil['valorcsp'];
				$Perfil .= "<option value=\"".$LnPerfil['valorcsp']."\">".$MaskPerfil[0]."</option>";
				}
			}
		}
		
	if( empty($Perfil)) $Perfil = "<option value=\"0\">".$_TRA['nepc']."</option>";
	return $Perfil;
}

function gerarNums($qtd, $minimo, $limite, $email){
	$numbers = "";
    for($i = 0; $i < $qtd; $i++){
        do {
            $bol = FALSE;
            $num = rand($minimo, $limite);
            $num = str_pad($num, 1, "0", STR_PAD_LEFT);
 
        } while($bol == TRUE); // Caso o valor seja true, será gerado um novo numero
		$numbers .= $num;
    }
	
	$letras = substr($email, 0, 3);
	$usuario = $letras.$numbers;
	
	$VerificarTesteUsuario = VerificarTesteUsuario($usuario);
	
	if($VerificarTesteUsuario == 1){
		gerarNums($qtd, $minimo, $limite, $email);
	}

 return array($usuario,$numbers);
}

function VerificarTesteUsuario($usuario){
	include("conexao.php");
	
	$SQL = "SELECT usuario FROM admin WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0) return 1;
	
	$SQL = "SELECT usuario FROM rev WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0) return 1;
	
	$SQL = "SELECT usuario FROM usuario WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0) return 1;
	
	$SQL = "SELECT usuario FROM teste WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0) return 1;
	
	return 2;
}

function EntrarSite($url, $login, $senha){
	
			$ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_USERPWD, $login . ":" . $senha);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			curl_setopt($ch, CURLOPT_HEADER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_UNRESTRICTED_AUTH, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30); // TIME OUT is 5 seconds
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($ch);
            curl_close($ch);
			
			return $response;
}

function EntrarVerificarServer($url, $login, $senha){
	
			$ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_USERPWD, $login . ":" . $senha);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
			curl_setopt($ch, CURLOPT_HEADER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_UNRESTRICTED_AUTH, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            $response = curl_exec($ch);
            curl_close($ch);
			
			return $response;
}

function VerificarStatusServidor($perfil){
	include("conexao.php");
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->execute();
	$LnPerfil = $SQLPerfil->fetch();
		
		$painel = $LnPerfil['painel'];
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users";
		$EntrarSite = EntrarVerificarServer($url, $usuario, $senha);
		$state = cut_str($EntrarSite, "<proxy-users count=\"", "\"");	
						
	return $state;
}

function VerificarUsoServidor($UrlPainel){
	include("conexao.php");
		$block = "N";
		$SQLP = "SELECT * FROM painel WHERE url = :url AND block = :block";
		$SQLP = $painel_geral->prepare($SQLP);
		$SQLP->bindParam(':url', $UrlPainel, PDO::PARAM_STR);
		$SQLP->bindParam(':block', $block, PDO::PARAM_STR);
		$SQLP->execute();
		$LnP = $SQLP->fetch();
		
				
		$url = $LnP['url'];
		$porta = $LnP['porta'];
		$usuario = $LnP['usuario'];
		$senha = $LnP['senha'];
		$protocolo = $LnP['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users";
		$EntrarSite = EntrarVerificarServer($url, $usuario, $senha);
		$state = cut_str($EntrarSite, "<proxy-users count=\"", "\"");	
						
	return $state;
}

function VerificarStatusOnline($caduser, $rev, $status, $perfil){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	if($perfil == "T"){
		$usuario = InfoUser(2);
		$SQLUser = "SELECT perfil FROM rev WHERE usuario = :usuario UNION SELECT perfil FROM admin WHERE usuario = :usuario";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		$perfil = $LnUser['perfil'];
		$perfil = str_replace("][","],[",$perfil);
	}
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$verificar = "S";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado AND verificar = :verificar";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':verificar', $verificar, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users&hide-inactive=false&profile=".$perfil;
		$EntrarSite = EntrarSite($url, $usuario, $senha);
		$pag = cut_str($EntrarSite, "<proxy-users", "</proxy-users>");	
		$body .= cut_str($pag, ">", NULL);
	}
	
		$VerificarUserStatus = VerificarUserStatus($caduser, $rev);
	
		$e = explode("<user name", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$active = cut_str($e[$i], "active=\"", "\"");
			$profile = cut_str($e[$i], "profile=\"", "\"");
			$connected = cut_str($e[$i], "connected=\"", "\"");			
			$host = cut_str($e[$i], "host=\"", "\"");	
			$canal = cut_str($e[$i], "\" name=\"", "\"");
			$duration = cut_str($e[$i], "duration=\"", "\"");
			
				if( ($status == "on") && ($active == "false") ) continue;
				if( ($status == "off") && ($active == "true") ) continue;
			
			if(in_array($name, $VerificarUserStatus)) {
				$valor[] = 	array($name, $connected, $host, $active, $profile, $canal, $duration);
			}
		}
	
	return $valor;
}

function VerificarStatusDesconectado($caduser, $rev, $perfil){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	if($perfil == "T"){
		$usuario = InfoUser(2);
		$SQLUser = "SELECT perfil FROM rev WHERE usuario = :usuario UNION SELECT perfil FROM admin WHERE usuario = :usuario";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		$perfil = $LnUser['perfil'];
		$perfil = str_replace("][","],[",$perfil);
	}
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$verificar = "S";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado AND verificar = :verificar";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':verificar', $verificar, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=last-seen&profile=".$perfil;
		$EntrarSite = EntrarSite($url, $usuario, $senha);

		$pag = cut_str($EntrarSite, "<last-seen", "</last-seen>");
		$body .= cut_str($pag, ">", NULL);
	}
	
		$VerificarUserStatus = VerificarUserStatus($caduser, $rev);
	
		$e = explode("<entry", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$profile = cut_str($e[$i], "profile=\"", "\"");
			$last_login = cut_str($e[$i], "last-login=\"", "\"");
			$last_seen = cut_str($e[$i], "last-seen=\"", "\"");
			$host = cut_str($e[$i], "host=\"", "\"");	
			$log = cut_str($e[$i], "user-log=\"", "\"");
						
			if(in_array($name, $VerificarUserStatus)) {
				$valor[] = 	array($name, $last_login, $last_seen, $host, $profile, $log);
			}
		}
	
	return $valor;
}

function VerificarStatusFalhado($caduser, $rev){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	$usuario = InfoUser(2);
	$SQLUser = "SELECT perfil FROM rev WHERE usuario = :usuario UNION SELECT perfil FROM admin WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$perfil = $LnUser['perfil'];
	$perfil = str_replace("][","],[",$perfil);
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$verificar = "S";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado AND verificar = :verificar";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':verificar', $verificar, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=login-failures&profile=".$perfil;
		$EntrarSite = EntrarSite($url, $usuario, $senha);

		$pag = cut_str($EntrarSite, "<login-failures", "</login-failures>");
		$body .= cut_str($pag, ">", NULL);
	}
	
		$VerificarUserStatus = VerificarUserStatus($caduser, $rev);
	
		$e = explode("<entry", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$context = cut_str($e[$i], "context=\"", "\"");
			$last_failure = cut_str($e[$i], "last-failure=\"", "\"");
			$first_failure = cut_str($e[$i], "first-failure=\"", "\"");	
			$failure_count = cut_str($e[$i], "failure-count=\"", "\"");	
			$host = cut_str($e[$i], "host=\"", "\"");
			$reason = cut_str($e[$i], "reason=\"", "\"");	
						
			if(in_array($name, $VerificarUserStatus)) {
				$valor[] = array($name, $context, $last_failure, $first_failure, $failure_count, $host, $reason);
			}
		}
	
	return $valor;
}

function VerificarStatusLogs($caduser, $rev, $perfil, $status){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	if($perfil == "T"){
		$usuario = InfoUser(2);
		$SQLUser = "SELECT perfil FROM rev WHERE usuario = :usuario UNION SELECT perfil FROM admin WHERE usuario = :usuario";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		$perfil = $LnUser['perfil'];
		$perfil = str_replace("][","],[",$perfil);
	}
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$verificar = "S";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado AND verificar = :verificar";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':verificar', $verificar, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users&profile=".$perfil;
		$EntrarSite = EntrarSite($url, $usuario, $senha);

		$pag = cut_str($EntrarSite, "<proxy-users", "</proxy-users>");
		$body .= cut_str($pag, ">", NULL);
	}
	
		$VerificarUserStatus = VerificarUserStatus($caduser, $rev);
	
		$e = explode("<user name", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$active = cut_str($e[$i], "active=\"", "\"");
			$profile = cut_str($e[$i], "profile=\"", "\"");
			$avgecminterval = cut_str($e[$i], "avg-ecm-interval=\"", "\"");	
			$host = cut_str($e[$i], "host=\"", "\"");
			$canal = cut_str($e[$i], "\" name=\"", "\"");
			$time = cut_str($e[$i], "last-transaction=\"", "\"");
			$ecmcount = cut_str($e[$i], "ecm-count=\"", "\"");
			$flags = cut_str($e[$i], "flags=\"", "\"");
			
				if( ($status == "on") && ($active == "false") ) continue;
				if( ($status == "off") && ($active == "true") ) continue;
						
			if(in_array($name, $VerificarUserStatus)) {
				$valor[] = 	array($name, $avgecminterval, $host, $active, $profile, $canal, $time, $ecmcount, $flags);
			}
		}
	
	return $valor;
}

function VerificarStatusReshare($caduser, $rev, $perfil){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	if($perfil == "T"){
		$usuario = InfoUser(2);
		$SQLUser = "SELECT perfil FROM rev WHERE usuario = :usuario UNION SELECT perfil FROM admin WHERE usuario = :usuario";
		$SQLUser = $painel_user->prepare($SQLUser);
		$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		$perfil = $LnUser['perfil'];
		$perfil = str_replace("][","],[",$perfil);
	}
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$verificar = "S";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado AND verificar = :verificar";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':verificar', $verificar, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users&profile=".$perfil;
		$EntrarSite = EntrarSite($url, $usuario, $senha);

		$pag = cut_str($EntrarSite, "<proxy-users", "</proxy-users>");
		$body .= cut_str($pag, ">", NULL);
	}
	
		$VerificarUserStatus = VerificarUserStatus($caduser, $rev);
	
		$e = explode("<user name", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$profile = cut_str($e[$i], "profile=\"", "\"");
			$host = cut_str($e[$i], "host=\"", "\"");
			$connected = cut_str($e[$i], "connected=\"", "\"");
			$duration = cut_str($e[$i], "duration=\"", "\"");
			$flags = cut_str($e[$i], "flags=\"", "\"");
			
			if(substr_count($flags, "Z") > 0){		
				if(in_array($name, $VerificarUserStatus)) {
					$valor[] = 	array($name, $profile, $host, $connected, $duration, $flags);
				}
			}
		}
	
	return $valor;
}


function VerificarUserStatus($UserOnline, $rev){
	include("conexao.php");
	$Return = array();
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
		
	$FindRev = $rev == "S" ? "FIND_IN_SET(CadUser,:CadUser)" : "CadUser = :CadUser";
	
	$SQL = "SELECT usuario FROM usuario WHERE ".$FindRev;
	$SQL = $painel_user->prepare($SQL);
	if($rev == "S") $SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	if($rev == "N") $SQL->bindParam(':CadUser', $UserOnline, PDO::PARAM_STR);
	$SQL->execute();
	while($LnUser = $SQL->fetch()){
		$Return[] = $LnUser['usuario'];
	}
		
	$SQL = "SELECT usuario FROM teste WHERE ".$FindRev;
	$SQL = $painel_user->prepare($SQL);
	if($rev == "S") $SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	if($rev == "N") $SQL->bindParam(':CadUser', $UserOnline, PDO::PARAM_STR);
	$SQL->execute();
	while($LnTeste = $SQL->fetch()){
		$Return[] = $LnTeste['usuario'];
	}

	return $Return;
		
}

function OrganizarHora($hora){
	include_once(Idioma(1));
	global $_TRA;
	$e = explode(" ", $hora);
	
	if($e[2] == "Jan"){
		$mes = "01";   
	}
	elseif($e[2] == "Feb"){
		$mes = "02";  
	}
	elseif($e[2] == "Mar"){
		$mes = "03";  
	}
	elseif($e[2] == "Apr"){
		$mes = "04";  
	}
	elseif($e[2] == "May"){
		$mes = "05";   
	}
	elseif($e[2] == "Jun"){
		$mes = "06";  
	}
	elseif($e[2] == "Jul"){
		$mes = "07";  
	}
	elseif($e[2] == "Aug"){
		$mes = "08";  
	}
	elseif($e[2] == "Sep"){
		$mes = "09";  
	}
	elseif($e[2] == "Oct"){
		$mes = "10";  
	}
	elseif($e[2] == "Nov"){
		$mes = "11";  
	}
	elseif($e[2] == "Dec"){
		$mes = "12";  
	}
	
	return $e[1]."/".$mes."/".$e[3]." ".$_TRA['ass']." ".$e[4];
}

function curl($url,$cookies,$post,$header=1){
		$ch = @curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, $header);
		if ($cookies) curl_setopt($ch, CURLOPT_COOKIE, $cookies);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20100101 Firefox/12.0');
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_REFERER,$url); 
		if ($post){
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $post); 
		}
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE); 
		curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($ch, CURLOPT_TIMEOUT, 30); 
		curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, 20);
		$page = curl_exec( $ch);
		curl_close($ch); 
		return $page;
}

function CurlXml($url,$cookies,$post,$header=1){
		$ch = @curl_init();
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_HEADER, $header);
		if ($cookies) curl_setopt($ch, CURLOPT_COOKIE, $cookies);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20100101 Firefox/12.0');
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_REFERER,$url); 
		if ($post){
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $post); 
		}
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE); 
		curl_setopt ($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($ch, CURLOPT_TIMEOUT, 5); 
		curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, 5);
		$page = curl_exec( $ch);
		curl_close($ch); 
		return $page;
}

function IPInfo($ip){
	$url = "http://ipinfo.io/".$ip."/json";
	$data = curl($url,'','');
	
	$hostname = cut_str($data, '"hostname": "', '"');
	$city = cut_str($data, '"city": "', '"');	
	$region = cut_str($data, '"region": "', '"');	
	$country = cut_str($data, '"country": "', '"');	
	$loc = cut_str($data, '"loc": "', '"');	
	$org = cut_str($data, '"org": "', '"');	
	
	return array($hostname, $city, $region, $country, $loc, $org);
	
}

function VerificarIPStatus($ip, $user){
	include_once(Idioma(1));
	global $_TRA;
	
	$IPInfo = IPInfo($ip);
	
	$ExibirIpInfo = "
 	<strong>".$_TRA['ip'].":</strong> ".$ip."<br>
 	<strong>".$_TRA['Hostname'].":</strong> ".$IPInfo[0]."<br>
 	<strong>".$_TRA['Cidade'].":</strong> ".$IPInfo[1]."<br>
 	<strong>".$_TRA['regiao'].":</strong> ".$IPInfo[2]."<br>
 	<strong>".$_TRA['pais'].":</strong> ".$IPInfo[3]."<br>
 	<strong>".$_TRA['localizacao'].":</strong> ".$IPInfo[4]."<br>
 	<strong>".$_TRA['Provedor'].":</strong> ".$IPInfo[5]."";
	
	$return = "<span type=\"button\" data-trigger=\"hover\" data-placement=\"top\" class=\"label label-warning pointer popover-dismiss\" title=\"\" data-content=\"".$ExibirIpInfo."\" data-original-title=\"".$user."\">".$ip."</span>";
	
	return $return;
}

function DerrubarUsuario($caduser, $perfil){
	include("conexao.php");
	$kick = false;
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	$LnPerfil = $SQLPerfil->fetch();
	
	$painel = $LnPerfil['painel'];
	$perfil = $LnPerfil['valorcsp'];
	$perfil = str_replace("[","",$perfil);
	$perfil = str_replace("]","",$perfil);
	$perfil = trim($perfil);
			
	$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
	$SQLPainel = $painel_geral->prepare($SQLPainel);
	$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
	$SQLPainel->execute();
	$LnPainel = $SQLPainel->fetch();
		
	$url = $LnPainel['url'];
	$porta = $LnPainel['porta'];
	$usuario = $LnPainel['usuario'];
	$senha = $LnPainel['senha'];
	$protocolo = $LnPainel['protocolo'];
		
	$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=kick-user&name=".trim($caduser);
	$EntrarSite = EntrarSite($url, $usuario, $senha);
	
	$kick = cut_str($EntrarSite, "command=\"kick-user\" success=\"", "\"");
	if($kick == "true"){
			return true;
	}
		
	return $kick;
}

function is_curl_installed() {
	
    if  (in_array  ('curl', get_loaded_extensions())) {
        return true;
    }
    else {
        return false;
    }
}

function VerificarStatusUsuario(){
	include("conexao.php");
	$body = "";
	$valor = array();
	
	$UserOnline = InfoUser(2);
	$SQLUser = "SELECT perfil FROM ".SelectTabela()." WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $UserOnline, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$perfil = $LnUser['perfil'];
	$perfil = str_replace("][","],[",$perfil);
	
	//Verificar o ID do Painel no Perfil
	$bloqueado = "N";
	$SQLPerfil = "SELECT painel, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPerfil->execute();
	
	while($LnPerfil = $SQLPerfil->fetch()){
		$painel = $LnPerfil['painel'];
		$perfil = $LnPerfil['valorcsp'];
		$perfil = str_replace("[","",$perfil);
		$perfil = str_replace("]","",$perfil);
		$perfil = trim($perfil);
			
		$SQLPainel = "SELECT url, porta, usuario, senha, protocolo FROM painel WHERE id = :id";
		$SQLPainel = $painel_geral->prepare($SQLPainel);
		$SQLPainel->bindParam(':id', $painel, PDO::PARAM_STR);
		$SQLPainel->execute();
		$LnPainel = $SQLPainel->fetch();
		
		$url = $LnPainel['url'];
		$porta = $LnPainel['porta'];
		$usuario = $LnPainel['usuario'];
		$senha = $LnPainel['senha'];
		$protocolo = $LnPainel['protocolo'];
		
		$url = $protocolo."://".$url.":".$porta."/xmlHandler?command=proxy-users&hide-inactive=false&profile=".$perfil."&name=".$UserOnline;
		$EntrarSite = EntrarSite($url, $usuario, $senha);
		$pag = cut_str($EntrarSite, "<proxy-users", "</proxy-users>");	
		$body .= cut_str($pag, ">", NULL);
	}
		
		$e = explode("<user name", $body);
		for($i = 0; $i < count($e); $i++){
			
			$name = cut_str($e[$i], "name=\"", "\"");
			$active = cut_str($e[$i], "active=\"", "\"");
			$profile = cut_str($e[$i], "profile=\"", "\"");
			$host = cut_str($e[$i], "host=\"", "\"");	
			$canal = cut_str($e[$i], "\" name=\"", "\"");
				
				if(!empty($name)){	
					$valor[] = 	array($active, $host, $profile, $canal);
				}
		}
	
	return $valor;
}

function PingAddress($host, $port, $timeout = 1){ 
  $tB = microtime(true); 
  $fP = @fsockopen($host, $port, $errno, $errstr, $timeout); 
  if (!$fP) { 
  	 $fP = @fsockopen($host, $port, $errno, $errstr, $timeout); 
	 if (!$fP) { 
 	 	return 0; 
	 }
  } 
  $tA = microtime(true); 
  return round((($tA - $tB) * 1000), 0); 
}

function VerificarVencimento(){
	include("conexao.php");
	$EnviarEmailSend = 0;
	$EnviarSMSSend = 0;
	
	$bloqueado = "N";
	$SQLTempo = "SELECT tempo FROM tempovencimento WHERE bloqueado = :bloqueado";
	$SQLTempo = $painel_geral->prepare($SQLTempo);
	$SQLTempo->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLTempo->execute();
	
	if($SQLTempo){
	
	$Tempo = "";
	while($LnTempo = $SQLTempo->fetch()){
		$t = strtotime(date('Y-m-d', strtotime("+".$LnTempo['tempo']." days",time())));
		$Tempo .= $t.",";
	}
	
	$data_premio = substr($Tempo,0,-1);	
	$DataEnviado = strtotime(date('Y-m-d'));
	$VencEmail = "S";
	$VencSMS = "S";
	
	$SQLUser = "SELECT CadUser, nome, usuario, senha, data_premio, perfil, email, celular, VencEmail, VencSMS, DataEnviado FROM rev WHERE VencEmail = :VencEmail AND DataEnviado < :DataEnviado AND FIND_IN_SET(data_premio,:data_premio) OR VencSMS = :VencSMS AND DataEnviado < :DataEnviado AND FIND_IN_SET(data_premio,:data_premio) UNION SELECT CadUser, nome, usuario, senha, data_premio, perfil, email, celular, VencEmail, VencSMS, DataEnviado FROM usuario WHERE VencEmail = :VencEmail AND DataEnviado < :DataEnviado AND FIND_IN_SET(data_premio,:data_premio) OR VencSMS = :VencSMS AND DataEnviado < :DataEnviado AND FIND_IN_SET(data_premio,:data_premio) LIMIT 1";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':VencEmail', $VencEmail, PDO::PARAM_STR);
	$SQLUser->bindParam(':VencSMS', $VencSMS, PDO::PARAM_STR);
	$SQLUser->bindParam(':DataEnviado', $DataEnviado, PDO::PARAM_STR);
	$SQLUser->bindParam(':data_premio', $data_premio, PDO::PARAM_STR);
	$SQLUser->execute();
	
	if($SQLUser){
			
	$LnUser = $SQLUser->fetch();
	$CadUser = $LnUser['CadUser'];
			
	$nome = $LnUser['nome'];
	$usuario = $LnUser['usuario'];
	$senha = $LnUser['senha'];
	$perfil = $LnUser['perfil'];
	$data_premio = date('d/m/Y', $LnUser['data_premio']);
	$email = $LnUser['email'];
	$celular = $LnUser['celular'];
	$VencEmail = $LnUser['VencEmail'];
	$VencSMS = $LnUser['VencSMS'];
	$DataEnviadoUser = $LnUser['DataEnviado'];
	
				//Atualiza a data de envio do rev
				$SQL = "UPDATE rev SET
				DataEnviado = :DataEnviado WHERE usuario = :usuario";
				$SQL = $painel_user->prepare($SQL);
				$SQL->bindParam(':DataEnviado', $DataEnviado, PDO::PARAM_STR); 
				$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
				$SQL->execute(); 
				
				//Atualiza a data de envio do user
				$SQL = "UPDATE usuario SET
				DataEnviado = :DataEnviado WHERE usuario = :usuario";
				$SQL = $painel_user->prepare($SQL);
				$SQL->bindParam(':DataEnviado', $DataEnviado, PDO::PARAM_STR); 
				$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
				$SQL->execute(); 
				
	$ArrayPerfil = array();
	$ex = explode('[',$perfil);
	for($i = 1; $i < count($ex); $i++){
		$ArrayPerfil[] = "[".$ex[$i];
	}
		
	//Enviar Email
	$VerificarEmailUser = VerificarEmailUser($CadUser, 'Vencimento');
		
	if( (!empty($email)) && ($VencEmail == "S") && ($VerificarEmailUser == false) && ($DataEnviadoUser < $DataEnviado) ){
	$SelecionarModelo = SelecionarModelo($CadUser, 'Vencimento', $usuario, $senha, $nome, $data_premio, $ArrayPerfil);
	
	$bloqueado = "N";
	$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLUser = $painel_geral->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	
	$EnviarEmailSend = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $email, $SelecionarModelo[0], $SelecionarModelo[1], NULL);
	}
	
	//Enviar SMS
	$VerificarSMSUser = VerificarSMSUser($CadUser, 'Vencimento');
	if( (!empty($celular)) && ($VencSMS == "S") && ($VerificarSMSUser == false) && ($DataEnviadoUser < $DataEnviado) ){
		$SelecionarModeloSMS = SelecionarModeloSMS($CadUser, 'Vencimento', $usuario, $senha, $nome, $data_premio, $ArrayPerfil);
		$EnviarSMSSend = EnviarSMS($CadUser, $SelecionarModeloSMS, $celular);
	}
	
		}
	}
}

function VerificarTipo($tipo){
	include("conexao.php");
	
	$SQLP = "SELECT tipo FROM perfil WHERE tipo = :tipo";
	$SQLP = $painel_geral->prepare($SQLP);
	$SQLP->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQLP->execute();
	$Total = count($SQLP->fetchAll());
	
	return $Total;	
}


function VerificarTipoPerfil($perfil){
	include("conexao.php");
	
	$perfil = str_replace("][","],[",$perfil);
	
	$tipo = "";
	$SQLP = "SELECT tipo FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp)";
	$SQLP = $painel_geral->prepare($SQLP);
	$SQLP->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLP->execute();
	while($Ln = $SQLP->fetch()){
		$tipo .= " ".$Ln['tipo'];
	}
	
	return $tipo;	
}

function VerificarTipoPerfilInd($perfil){
	include("conexao.php");
		
	$SQLP = "SELECT tipo FROM perfil WHERE valorcsp = :valorcsp";
	$SQLP = $painel_geral->prepare($SQLP);
	$SQLP->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLP->execute();
	$Ln = $SQLP->fetch();
	$tipo = $Ln['tipo'];
	
	return $tipo;	
}

function GerarRelatorio($UserOnline, $rev, $perfil, $tipo, $Ativo, $Vencido, $Bloqueado, $PesquisaEntreData){
	include("conexao.php");
	$relatorio = array();
		
	if($rev == "S"){
		$CadUser = ArvoreAdminRev($UserOnline);
		$CadUser[] = $UserOnline;
		$CadUser = implode(',', $CadUser);
		$Pesq = "FIND_IN_SET(CadUser,:CadUser) OR usuario = :usuario";
	}
	else{
		$CadUser = $UserOnline;
		$Pesq = "usuario = :CadUser";
	}
	
	$SQL = "SELECT CadUser, nome, usuario, ValorCobrado, ValorCobradoCabo, data_premio FROM admin WHERE ".$Pesq;
	$SQL .= " UNION SELECT CadUser, nome, usuario, ValorCobrado, ValorCobradoCabo, data_premio FROM rev WHERE ".$Pesq;
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	if($rev == "S") $SQL->bindParam(':usuario', $UserOnline, PDO::PARAM_STR);
	$SQL->execute();
	
	while($Ln = $SQL->fetch()){
		$salvar = array();
		$CadUser = $Ln['CadUser'];
		$nome = $Ln['nome'];
		$usuario = $Ln['usuario'];
		$ValorCobradoSAT = $Ln['ValorCobrado'];
		$ValorCobradoCabo = $Ln['ValorCobradoCabo'];
		$data_premio = $Ln['data_premio'];
		
		if($perfil == "T"){
			$ContarUsuarioTotal = ContarUsuarioRelatorio($usuario, $tipo);
		}
		else{
			$ContarUsuarioTotal = ContarUsuarioTotalPerfil($usuario, $perfil);
		}
		
		$ativosSAT = $ContarUsuarioTotal[0];
		$ativosConexaoSAT = $ContarUsuarioTotal[1];
		$ativosCAB = $ContarUsuarioTotal[2];
		$ativosConexaoCAB = $ContarUsuarioTotal[3];
		$TotalAtivos = $ContarUsuarioTotal[4];
		
		//SAT	
		$ACobrarSAT = $ativosSAT * $ValorCobradoSAT;
		$ACobrarSAT = number_format($ACobrarSAT, 2, ',', '');
		$ACobrarSAT = VerRepDin()." ".$ACobrarSAT;
		
		$ACobrarConexaoSAT = $ativosConexaoSAT * $ValorCobradoSAT;
		$ACobrarConexaoSAT = number_format($ACobrarConexaoSAT, 2, ',', '');
		$ACobrarConexaoSAT = VerRepDin()." ".$ACobrarConexaoSAT;
		
		$ValorCobradoSAT = number_format($ValorCobradoSAT, 2, ',', '');
		$ValorCobradoSAT = VerRepDin()." ".$ValorCobradoSAT;
		
		//CAB	
		$ACobrarCAB = $ativosCAB * $ValorCobradoCabo;
		$ACobrarCAB = number_format($ACobrarCAB, 2, ',', '');
		$ACobrarCAB = VerRepDin()." ".$ACobrarCAB;
		
		$ACobrarConexaoCAB = $ativosConexaoCAB * $ValorCobradoCabo;
		$ACobrarConexaoCAB = number_format($ACobrarConexaoCAB, 2, ',', '');
		$ACobrarConexaoCAB = VerRepDin()." ".$ACobrarConexaoCAB;
		
		$ValorCobradoCabo = number_format($ValorCobradoCabo, 2, ',', '');
		$ValorCobradoCabo = VerRepDin()." ".$ValorCobradoCabo;
				
		if( ($CadUser == $UserOnline) || ($usuario == $UserOnline) ){
			
				$salvar[] = $perfil;
				$salvar[] = $nome;
				$salvar[] = $usuario;
				$salvar[] = $ValorCobradoSAT;
				$salvar[] = $ativosSAT;
				$salvar[] = $ativosConexaoSAT;
				$salvar[] = $ACobrarSAT;
				$salvar[] = $ACobrarConexaoSAT;
				$salvar[] = $ValorCobradoCabo;
				$salvar[] = $ativosCAB;
				$salvar[] = $ativosConexaoCAB;
				$salvar[] = $ACobrarCAB;
				$salvar[] = $ACobrarConexaoCAB;
				$salvar[] = $CadUser;
				$salvar[] = $data_premio;
				$relatorio[] = $salvar;
		}
	}
	
	
	return $relatorio;
}

function VerRepDin(){
	$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
	if($idioma == "br"){
		return "R$";
	}
	elseif($idioma == "en"){
		return "US$";
	}
	elseif($idioma == "es"){
		return "€";
	}
	elseif($idioma == "it"){
		return "€";
	}
	elseif($idioma == "ge"){
		return "€";
	}
	elseif($idioma == "fr"){
		return "€";
	}
	else{
		return "R$";
	}
}

function ArvoreAdminRevPerfil($CadUser, $perfil){	
	include("conexao.php");
	$Arvore = array();
	
	$SQL = "SELECT usuario FROM admin WHERE CadUser = :CadUser AND perfil LIKE '%".$perfil."%' UNION SELECT usuario FROM rev WHERE CadUser = :CadUser AND perfil LIKE '%".$perfil."%'";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	
	if($SQL){
		while($LnSelect = $SQL->fetch()){
			if($LnSelect['usuario'] != $CadUser){
				$Arvore[] = $LnSelect['usuario'];
				$SomarArvore = ArvoreAdminRevPerfil($LnSelect['usuario'], $perfil);
				$Arvore = array_merge($Arvore, $SomarArvore);
			}
		}
	}
	
	return array_values(array_unique($Arvore));
}

function ContarUsuarioTotalPerfil($UserOnline, $perfil){
	include("conexao.php");	
	
	$CadUser = ArvoreAdminRevPerfil($UserOnline, $perfil);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
	
	$ativo = 0;
	$ativoC = 0;
	$esgotado = 0;
	$bloqueado = 0;
		
	$SQLUser = "SELECT bloqueado, data_premio, conexao FROM usuario WHERE FIND_IN_SET(CadUser,:CadUser) AND perfil LIKE '%".$perfil."%'";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();

	$DataAtual = strtotime(date('Y-m-d'));
	while($LnUser = $SQLUser->fetch()){
		if( ($LnUser['bloqueado'] == "N") && ($LnUser['data_premio'] >= $DataAtual) ){
			$ativo += 1;
			$ativoC += $LnUser['conexao'];
		}
		elseif( ($LnUser['data_premio'] < $DataAtual) ){
			$esgotado += 1;
		}
		elseif( ($LnUser['bloqueado'] == "S") ){
			$bloqueado += 1;
		}
	}
	
	return array($ativo, $esgotado, $bloqueado, $ativoC);
}

function SelecionarNomePerfil($perfil){
	include("conexao.php");	
	
	$bloqueado = "N";
	$SQLPerfil = "SELECT id FROM perfil WHERE valorcsp = :valorcsp AND bloqueado = :bloqueado";
	$SQLPerfil = $painel_geral->prepare($SQLPerfil);
	$SQLPerfil->bindParam(':valorcsp', $perfil, PDO::PARAM_STR); 
	$SQLPerfil->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
	$SQLPerfil->execute();
	$LnPerfil = $SQLPerfil->fetch();
	
	$UserOnline = InfoUser(2);
	$MaskPerfil = MaskPerfil($UserOnline, $LnPerfil['id']);
	
	return $MaskPerfil[0];
}

function ExcluirPorGrupo($id_grupo){
	include("conexao.php");
	
	//painel_acessos 
	$SQL = "SHOW TABLES";
	$SQL = $painel_acessos->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_acessos->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
		$SQLDel = "DELETE FROM ".$Ln[0]." WHERE id_grupo = :id_grupo";
		$SQLDel = $painel_acessos->prepare($SQLDel);
		$SQLDel->bindParam(':id_grupo', $id_grupo, PDO::PARAM_STR); 
		$SQLDel->execute();
		}
	}
		return 1;	
}

function SelecionarFormas($id, $tipo, $i, $SAT = NULL){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	$CadUser = InfoUser(4);
	
	$retorn = "";
	$bloqueado = "N";
	
	$SQLBanco = "SELECT id FROM contabancaria WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLBanco = $painel_geral->prepare($SQLBanco);
	$SQLBanco->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLBanco->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLBanco->execute();
	$TotalBanco = count($SQLBanco->fetchAll());
	
	if($TotalBanco > 0){
		$retorn .= "<div class=\"panel-footer\"><button onclick=\"ProcessarCompra(1,'".$id."','".$tipo."','".$i."','".$SAT."');\" class=\"btn btn-success btn-block\">".$_TRA['ContaBancaria']."</button></div>";
	}
	
	$SQLMercado = "SELECT id FROM contamercadopago WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLMercado = $painel_geral->prepare($SQLMercado);
	$SQLMercado->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLMercado->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLMercado->execute();
	$TotalMercado = count($SQLMercado->fetchAll());
	
	if($TotalMercado > 0){
		$retorn .= "<div class=\"panel-footer\"><button onclick=\"ProcessarCompra(2,'".$id."','".$tipo."','".$i."','".$SAT."');\" class=\"btn btn-danger btn-block\">".$_TRA['MercadoPago']."</button></div>";
	}
	
	$SQLPag = "SELECT id FROM contapagseguro WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLPag = $painel_geral->prepare($SQLPag);
	$SQLPag->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPag->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPag->execute();
	$TotalPag = count($SQLPag->fetchAll());
	
	if($TotalPag > 0){
		$retorn .= "<div class=\"panel-footer\"><button onclick=\"ProcessarCompra(3,'".$id."','".$tipo."','".$i."','".$SAT."');\" class=\"btn btn-warning btn-block\">".$_TRA['PagSeguro']."</button></div>";
	}
	
	$SQLPay = "SELECT id FROM contapaypal WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
	$SQLPay = $painel_geral->prepare($SQLPay);
	$SQLPay->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQLPay->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPay->execute();
	$TotalPay = count($SQLPay->fetchAll());
	
	if($TotalPay > 0){
		$retorn .= "<div class=\"panel-footer\"><button onclick=\"ProcessarCompra(4,'".$id."','".$tipo."','".$i."','".$SAT."');\" class=\"btn btn-info btn-block\">".$_TRA['PayPal']."</button></div>";
	}
	
	return $retorn;
}

function my_decrypt($data, $key='XXYM0LTtOwwDO7wZ0VVz') {

	$encryption_key = base64_decode($key);
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);
}

function SelecionarComprar($tipoplano){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	$CadUser = InfoUser(4);
	$return = "";
	
	$SQL = "SELECT DISTINCT(perfil) FROM planos WHERE CadUser = :CadUser AND tipoplano = :tipoplano";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':tipoplano', $tipoplano, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	if($Total > 0){
		$SQL->execute();
		while($Ln = $SQL->fetch()){
			$perfil = $Ln['perfil'];
			$perfil = str_replace("][","___",$perfil);
			$perfil = str_replace("[","",$perfil);
			$perfil = str_replace("]","",$perfil);
			$perfil = trim($perfil);
			$return .= "<option data-content=\"".SelecionarPerfilComprar($Ln['perfil'])."\" value=\"".$perfil."\"></option>";
		}
		return $return;
	}
	else{
		return false;
	}
	
	return false;
}

function SelecionarPerfilComprar($perfil){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	$UserOnline = InfoUser(2);
	
	$Exibir = "";
	
	$ex = explode('[',$perfil);
	for($i = 1; $i < count($ex); $i++){
	$Perfil = "[".$ex[$i];
	
		$SQL = "SELECT perfil_icone.img, perfil.id FROM perfil_icone INNER JOIN perfil ON perfil_icone.id = perfil.imagem AND perfil.valorcsp = :perfil";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':perfil', $Perfil, PDO::PARAM_STR);
		$SQL->execute();
		$LnSelect = $SQL->fetch();
	
		$FotoPerfil = FotoPerfil($LnSelect['img']);
		$MaskPerfil = MaskPerfil($UserOnline, $LnSelect['id']);
	
		$Exibir .= "<img src='".$FotoPerfil."' width='16' height='16'>"." ".$MaskPerfil[0];
		$Exibir .= " ";
	}
		
	return $Exibir;
		
}

function GerarReferencia(){
		$pass = "";
        $salt = "abchefghjkmnpqrstuvwxyz0123456789";
        srand((double)microtime()*1000000);
        $i = 0;
        while ($i <= 30){
            $num = rand() % 33;
            $tmp = substr($salt, $num, 1);
            $pass = $pass . $tmp;
            $i++;
        }
	return strtoupper($pass);
}

function CodigoLiberacao(){
		$pass = "";
        $salt = "abchefghjkmnpqrstuvwxyz0123456789";
        srand((double)microtime()*1000000);
        $i = 0;
        while ($i <= 4){
            $num = rand() % 33;
            $tmp = substr($salt, $num, 1);
            $pass = $pass . $tmp;
            $i++;
        }
	return strtoupper($pass);
}

function DadosPagSeguro($CadUser){
	include("conexao.php");
		
	$SQL = "SELECT email, token FROM contapagseguro WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
		
	return array($Ln['email'], $Ln['token']);
}

function DadosMercadoPago($CadUser){
	include("conexao.php");
		
	$SQL = "SELECT clientid, clientsecret FROM contamercadopago WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
		
	return array($Ln['clientid'], $Ln['clientsecret']);
}

function DadosPayPal($CadUser){
	include("conexao.php");
		
	$SQL = "SELECT email, senha FROM contapaypal WHERE CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
		
	return array($Ln['email'], $Ln['senha']);
}

function SelecionarDadosMetodo($Referencia){
	include("conexao.php");
	
	$SQL = "SELECT CadUser, comprador, dias, valor, perfil, conexao, PrePago, Quantidade FROM comprar WHERE referencia = :referencia";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':referencia', $Referencia, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	return array($Ln['CadUser'], $Ln['comprador'], $Ln['dias'], $Ln['valor'], $Ln['perfil'], $Ln['conexao'], $Ln['PrePago'], $Ln['Quantidade']);
}

function VerificarTeste($comprador){
	include("conexao.php");
	
	//Seleciona a tabela de testes
	$SQL = "SELECT * FROM teste WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $comprador, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
		
	if($Total > 0){
		$SQL->execute();
		$Ln = $SQL->fetch();
		
		$CadUser = $Ln['CadUser'];
		$nome = $Ln['nome'];
		$sobrenome = $Ln['sobrenome'];
		$usuario = $Ln['usuario'];
		$senha = $Ln['senha'];
		$email = $Ln['email'];
		$celular = $Ln['celular'];
		$data_cadastro = $Ln['data_cadastro'];
		
		//Cadastra na Tabela Usuário
		$SQL = "INSERT INTO usuario (
				CadUser,
				nome,
            	sobrenome,
            	usuario,
				senha,
				email,
				celular,
				data_cadastro
            ) VALUES (
				:CadUser,
				:nome,
            	:sobrenome,
            	:usuario,
				:senha,
				:email,
				:celular,
				:data_cadastro
			)";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
		$SQL->bindParam(':nome', $nome, PDO::PARAM_STR); 
		$SQL->bindParam(':sobrenome', $sobrenome, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
		$SQL->bindParam(':senha', $senha, PDO::PARAM_STR); 
		$SQL->bindParam(':email', $email, PDO::PARAM_STR);
		$SQL->bindParam(':celular', $celular, PDO::PARAM_STR); 
		$SQL->bindParam(':data_cadastro', $data_cadastro, PDO::PARAM_STR);
		$SQL->execute(); 
		
		//Deleta do teste
		$SQL = "DELETE FROM teste WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
		$SQL->execute();
	}
	
	return false;
}

function AtualizarRetorno($CadUser, $comprador, $dias, $perfil, $conexao, $PrePago, $Quantidade){
	include("conexao.php");
	$DataAtual = strtotime(date('Y-m-d'));
	
	if($PrePago == "N"){
		$SQL = "SELECT data_premio FROM usuario WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $comprador, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
		$data_premio = $Ln['data_premio'];
		
			if($data_premio > $DataAtual){
				$DataAtualizar = $data_premio + (3600 * 24 * $dias);
			}
			else{
				$DataAtualizar = time() + (3600 * 24 * $dias);
			}
		
		//Atualizar Usuário
		$SQL = "UPDATE usuario SET
			conexao = :conexao,
			perfil = :perfil,
			data_premio = :data_premio
            WHERE CadUser = :CadUser AND usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);                    
		$SQL->bindValue(':conexao', $conexao);
		$SQL->bindValue(':perfil', $perfil);
		$SQL->bindValue(':data_premio', $DataAtualizar);
		$SQL->bindValue(':CadUser', $CadUser);
		$SQL->bindValue(':usuario', $comprador);
		$SQL->execute();
	}
	else{
		//Atualizar Revendedor
		$SQL = "UPDATE rev SET
			conexao = :conexao,
			perfil = :perfil,
			PrePago = :PrePago,
			Cota = :Cota,
			CotaDias = :CotaDias
            WHERE CadUser = :CadUser AND usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);                    
		$SQL->bindValue(':conexao', $conexao);
		$SQL->bindValue(':perfil', $perfil);
		$SQL->bindValue(':PrePago', $PrePago);
		$SQL->bindValue(':Cota', $Quantidade);
		$SQL->bindValue(':CotaDias', $dias);
		$SQL->bindValue(':CadUser', $CadUser);
		$SQL->bindValue(':usuario', $comprador);
		$SQL->execute();
		
	}
	
		return false;
}

function DadosComprador($comprador){
	include("conexao.php");
	
		$SQL = "(SELECT email, senha, nome, data_premio FROM usuario WHERE usuario = :usuario) UNION ALL (SELECT email, senha, nome, data_premio FROM rev WHERE usuario = :usuario)";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $comprador, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
		$email = $Ln['email'];
		$senha = $Ln['senha'];
		$nome = $Ln['nome'];
		$data_premio = $Ln['data_premio'];
		
		return array($email, $senha, $nome, $data_premio);
}

function CURLMercadoPago($url){
	$curl = curl_init();
	curl_setopt( $curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; rv:1.7.3) Gecko/20041001 Firefox/0.10.1" );
	curl_setopt ($curl, CURLOPT_URL, $url);
	curl_setopt ($curl, CURLOPT_RETURNTRANSFER, true);
	curl_setopt ($curl, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt ($curl, CURLOPT_CONNECTTIMEOUT, 20);
	$data = curl_exec($curl);
	curl_close($curl);
	
	return $data;
}

function LeituraTxt(){
	$fp = fopen("xml.txt", "r");
	$linha = fgets($fp);
	fclose($fp);
	
	return trim($linha);
}

function CriarTxt($texto){
	$fp = fopen("xml.txt", "w");
	$escreve = fwrite($fp, $texto);
	fclose($fp);
	
	return false;
}

function MaskPerfil($CadUser, $perfil){
	include("conexao.php");
	
	$AcessoOnline = InfoUser(3);
	
	if( $AcessoOnline == 3 ){
		$SQL = "SELECT CadUser FROM usuario WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
		$CadUser = $Ln['CadUser'];
	}
	elseif( $AcessoOnline == 4 ){
		$SQL = "SELECT CadUser FROM teste WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
		$CadUser = $Ln['CadUser'];
	}
	
	
	$bloqueado = "N";
	
	$ArvoreAdmin = ArvoreAdminExibir($CadUser);
	$ArvoreAdmin = array_reverse($ArvoreAdmin);
	$ArvoreAdmin[] = $CadUser;
	$ArvoreAdmin = array_reverse($ArvoreAdmin);
	
	$ArvoreRev = ArvoreRevExibir($CadUser);
	$ArvoreRev = array_reverse($ArvoreRev);
	$ArvoreRev[] = $CadUser;
	$ArvoreRev = array_reverse($ArvoreRev);
			
	for($i=0; $i < count($ArvoreRev); $i++){
	$SQL = "SELECT nome, url, porta FROM mascaraurl WHERE CadUser = :CadUser AND perfil = :perfil AND bloqueado = :bloqueado";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $ArvoreRev[$i], PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $perfil, PDO::PARAM_STR);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	$nome = empty($Ln['nome']) ? "" : $Ln['nome'];	
	$url = empty($Ln['url']) ? "" : $Ln['url'];
	$porta = empty($Ln['porta']) ? "" : $Ln['porta'];
	if(!empty($nome) && !empty($url) && !empty($porta)) return array($nome, $url, $porta);
	}
	
	for($i=0; $i < count($ArvoreAdmin); $i++){
	$SQL = "SELECT nome, url, porta FROM mascaraurl WHERE CadUser = :CadUser AND perfil = :perfil AND bloqueado = :bloqueado";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $ArvoreAdmin[$i], PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $perfil, PDO::PARAM_STR);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	$nome = empty($Ln['nome']) ? "" : $Ln['nome'];
	$url = empty($Ln['url']) ? "" : $Ln['url'];
	$porta = empty($Ln['porta']) ? "" : $Ln['porta'];
	if(!empty($nome) && !empty($url) && !empty($porta)) return array($nome, $url, $porta);
	}
	
	$SQL = "SELECT nome, url, porta FROM perfil WHERE id = :id AND bloqueado = :bloqueado";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':id', $perfil, PDO::PARAM_STR);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	$Ln = $SQL->fetch();
	
	$nome = empty($Ln['nome']) ? "" : $Ln['nome'];
	$url = empty($Ln['url']) ? "" : $Ln['url'];
	$porta = empty($Ln['porta']) ? "" : $Ln['porta'];
	
	return array($nome, $url, $porta);
	
}

function VerificarCaracter($dados){
	
	if(substr_count($dados, "\\") > 0){
		return array(true, "&#92;");
	}
	elseif(substr_count($dados, ">") > 0){
		return array(true, "&#62;");
	}
	elseif(substr_count($dados, "<") > 0){
		return array(true, "&#60;");
	}
	elseif(substr_count($dados, "/") > 0){
		return array(true, "&#47;");
	}
	elseif(substr_count($dados, "\"") > 0){
		return array(true, "&#34;");
	}
	elseif(substr_count($dados, "'") > 0){
		return array(true, "&#39;");
	}
	
	return array(false, NULL);
}

function VerificarInfoPre(){
	include("conexao.php");
	$Cota = 0;
	$CotaDias = 0;
	
	$CadUser = InfoUser(2);
	$PrePago = empty($_SESSION['PrePago']) ? "N" : $_SESSION['PrePago'];
	
	if($PrePago == "S"){
		$SQL = "SELECT Cota, CotaDias FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
	
		$Cota = empty($Ln['Cota']) ? 0 : $Ln['Cota'];
		$CotaDias = empty($Ln['CotaDias']) ? 0 : $Ln['CotaDias'];
	}
	
	return array($PrePago, $Cota, $CotaDias);
}

function VerificarComputadorLiberado(){
	include("conexao.php");
	
	if( !isset($_SESSION['LCLiberarComputador']) || !isset($_SESSION['LCcomputador']) ){
	
	$CadUser = InfoUser(2);
	$ativo = "S";
	
	$SQL = "SELECT codigo, ip FROM liberarcomputador WHERE CadUser = :CadUser AND ativo = :ativo";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':ativo', $ativo, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
		if($Total > 0){
			$SQL->execute();
			
			$_SESSION['LCcomputador'] = array();
			while($Ln = $SQL->fetch()){
				$codigo = $Ln['codigo'];
				$ip = $Ln['ip'];
				$CodigoIP = md5($codigo.$ip);
				array_push($_SESSION['LCcomputador'], $CodigoIP);
			}
			
			$_SESSION['LCLiberarComputador'] = "S";
						
			return array('S', $_SESSION['LCcomputador']);
		}
		else{
			
			$_SESSION['LCLiberarComputador'] = "N";
			$_SESSION['LCcomputador'] = "N";
			
			return array('N','N');
		}
	
	}
	
		return array($_SESSION['LCLiberarComputador'],$_SESSION['LCcomputador']);
}

function AtualizarUserBanco($antigo, $novo){
	include("conexao.php");
	
	$ArrayAcessos = array();
	$ArrayGeral = array();
	$ArrayUser = array();
		
	//painel_acessos
	$SQL = "SHOW TABLES";
	$SQL = $painel_acessos->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_acessos->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
			$ArrayAcessos[] = $Ln[0];
		}
		
	}
	
	for($i = 0; $i < count($ArrayAcessos); $i++){
		$SQL = "UPDATE ".$ArrayAcessos[$i]." SET
				CadUser = :CadUserNovo
           		WHERE CadUser = :CadUserVelho";
		$SQL = $painel_acessos->prepare($SQL);
		$SQL->bindParam(':CadUserNovo', $novo, PDO::PARAM_STR); 
		$SQL->bindParam(':CadUserVelho', $antigo, PDO::PARAM_STR); 
		$SQL->execute();
	}
				
	//painel_geral
	$SQL = "SHOW TABLES";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_geral->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
			$ArrayGeral[] = $Ln[0];
		}
	}
	
	for($i = 0; $i < count($ArrayGeral); $i++){
		$SQL = "UPDATE ".$ArrayGeral[$i]." SET
				CadUser = :CadUserNovo
           		WHERE CadUser = :CadUserVelho";
		$SQL = $painel_geral->prepare($SQL);
		$SQL->bindParam(':CadUserNovo', $novo, PDO::PARAM_STR); 
		$SQL->bindParam(':CadUserVelho', $antigo, PDO::PARAM_STR); 
		$SQL->execute();
	}
	
	//painel_user
	$SQL = "SHOW TABLES";
	$SQL = $painel_user->prepare($SQL);
	$SQL->execute();
	while($Ln = $SQL->fetch(PDO::FETCH_NUM)) { 
		$SQLTable = "SHOW FIELDS FROM ".$Ln[0]." WHERE Field = 'CadUser'";
		$SQLTable = $painel_user->prepare($SQLTable);
		$SQLTable->execute();
		$TotalResul = count($SQLTable->fetchAll());	
		
		if($TotalResul > 0){
			$ArrayUser[] = $Ln[0];
		}
	}
	
	for($i = 0; $i < count($ArrayUser); $i++){
		$SQL = "UPDATE ".$ArrayUser[$i]." SET
				CadUser = :CadUserNovo
           		WHERE CadUser = :CadUserVelho";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':CadUserNovo', $novo, PDO::PARAM_STR); 
		$SQL->bindParam(':CadUserVelho', $antigo, PDO::PARAM_STR); 
		$SQL->execute();
	}
	
	
		return true;	
}


function VerificarLimiteTeste($CadUser){
	include("conexao.php");
	
	$ArvoreRev = ArvoreRevExibir($CadUser);
	$ArvoreRev = array_reverse($ArvoreRev);
	$ArvoreRev[] = $CadUser;
	$ArvoreRev = array_reverse($ArvoreRev);
				
	for($i=0; $i < count($ArvoreRev); $i++){
		$Revendedor = $ArvoreRev[$i];
		
		$SQL = "SELECT LimiteTeste FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $Revendedor, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
				
		if(!empty($Ln['LimiteTeste'])) return $Ln['LimiteTeste'];
	}
	
	return 0;
	
}

function VerificarLimiteUser($CadUser){
	include("conexao.php");
	
	$ArvoreRev = ArvoreRevExibir($CadUser);
	$ArvoreRev = array_reverse($ArvoreRev);
	$ArvoreRev[] = $CadUser;
	$ArvoreRev = array_reverse($ArvoreRev);
				
	for($i=0; $i < count($ArvoreRev); $i++){
		$Revendedor = $ArvoreRev[$i];
		
		$SQL = "SELECT LimiteUser FROM rev WHERE usuario = :usuario";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':usuario', $Revendedor, PDO::PARAM_STR);
		$SQL->execute();
		$Ln = $SQL->fetch();
				
		if(!empty($Ln['LimiteUser'])) return $Ln['LimiteUser'];
	}
	
	return 0;
	
}

function VerificarCotaTeste($UserOnline){
	include("conexao.php");
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
			
	$SQL = "SELECT id FROM teste WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	return $Total;
}

function VerificarCotaUser($UserOnline){
	include("conexao.php");
	
	$CadUser = ArvoreAdminRev($UserOnline);
	$CadUser[] = $UserOnline;
	$CadUser = implode(',', $CadUser);
			
	$SQL = "SELECT id FROM usuario WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	return $Total;
}

function StatusPaypalMercadoPago($status){
	include_once(Idioma(1));
	global $_TRA;
	
	if($status == "pending"){
		$Ret = $_TRA['Aguardandopagamento'];
	}
	elseif($status == 'approved'){
		$Ret = $_TRA['Aprovado'];
	}
	elseif($status == 'in_process'){
		$Ret = $_TRA['Emprocesso'];
	}
	elseif($status == 'in_mediation'){
		$Ret = $_TRA['Emmediacao'];
	}
	elseif($status == 'rejected'){
		$Ret = $_TRA['Rejeitado'];
	}
	elseif($status == 'cancelled'){
		$Ret = $_TRA['Cancelado'];
	}
	elseif($status == 'refunded'){
		$Ret = $_TRA['Devolvido'];
	}

	return $Ret;
}

function StatusPagSeguro($status){
	include_once(Idioma(1));
	global $_TRA;
	
	if($status == 1){
		$Ret = $_TRA['Aguardandopagamento'];
	}
	elseif($status == 2){
		$Ret = $_TRA['Emanalise'];
	}
	elseif($status == 3){
		$Ret = $_TRA['Paga'];
	}
	elseif($status == 4){
		$Ret = $_TRA['disponivel'];
	}
	elseif($status == 5){
		$Ret = $_TRA['Emdisputa'];
	}
	elseif($status == 6){
		$Ret = $_TRA['Devolvida'];
	}
	elseif($status == 7){
		$Ret = $_TRA['Cancelada'];
	}
	elseif($status == 8){
		$Ret = $_TRA['Chargebackdebitado'];
	}
	elseif($status == 9){
		$Ret = $_TRA['Emcontestacao'];
	}
	
	return $Ret;
}

function ModeloCircular(){
	include("conexao.php");
	include_once(Idioma(1));
	global $_TRA;
	
	$bloqueado = "N";
	$tipo = "Email";
	$CadUser = InfoUser(2);
	$option = "<option value=\"0\">-- ".$_TRA['suo']." --</option>";

	$SQL = "SELECT id, assunto FROM email_modelo WHERE CadUser = :CadUser AND tipo = :tipo AND bloqueado = :bloqueado";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQL->execute();
	
	while($Ln = $SQL->fetch()){
		$option .= "<option value=\"".$Ln['id']."\">".$Ln['assunto']."</option>";
	}
	
	if(empty($option)) $option = "<option value=\"0\">".$_TRA['nemde']."</option>";
	
	return $option;
}

function ModeloCircularExibir($mensagem){
	include("conexao.php");
	
	$CadUser = InfoUser(2);
	
	//Informações do Usuário Emissor
	$SQLUser = "SELECT nome, email FROM admin WHERE usuario = :usuario UNION ALL SELECT nome, email FROM rev WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$NomeEmissor = empty($LnUser['nome']) ? $CadUser : $LnUser['nome'];
	$EmailEmissor = empty($LnUser['email']) ? '' : $LnUser['email'];
	
	$SQLInfo = "SELECT NomePainel FROM site_config";
	$SQLInfo = $painel_geral->prepare($SQLInfo);
	$SQLInfo->execute();
	$LnInfo = $SQLInfo->fetch();

	$NomePainel = empty($LnInfo['NomePainel']) ? 'CSPainel' : $LnInfo['NomePainel'];
	
	$mensagem = str_replace("[MEUEMAIL]",$EmailEmissor,$mensagem);
	$mensagem = str_replace("[MEUNOME]",$NomeEmissor,$mensagem);
	$mensagem = str_replace("[URLPAINEL]",UrlAtual(),$mensagem);
	$mensagem = str_replace("[NOMEPAINEL]",$NomePainel,$mensagem);
	
	return $mensagem;
}

function VerificarEmailTeste($CadUser, $email){
	include("conexao.php");

	$SQL = "SELECT * FROM email_teste WHERE CadUser = :CadUser AND email = :email";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':email', $email, PDO::PARAM_STR);
	$SQL->execute();
	$Total = count($SQL->fetchAll());
	
	return $Total;
}

?>