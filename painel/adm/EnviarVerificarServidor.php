<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

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
	$SQLPainel = "SELECT painel, nome, valorcsp FROM perfil WHERE FIND_IN_SET(valorcsp,:valorcsp) AND bloqueado = :bloqueado";
	$SQLPainel = $painel_geral->prepare($SQLPainel);
	$SQLPainel->bindParam(':valorcsp', $perfil, PDO::PARAM_STR);
	$SQLPainel->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
	$SQLPainel->execute();
	$TotalPainel = count($SQLPainel->fetchAll());
	
	$_SESSION['ServidorPerfil'] = array();
	
	if($TotalPainel > 0){
	
echo "

								<table class=\"table table-striped\" style=\"height: auto;\">
                                            <thead>
                                                <tr>
                                                    <th><center>".$_TRA['Servidor']."</center></th>
                                                    <th><center>".$_TRA['Operadora']."</center></th>
                                                    <th><center>".$_TRA['Status']."</center></th>
													
                                                </tr>
                                            </thead>
                                            <tbody style=\"height: auto;\">";
											
											$SQLPainel->execute();
											while($LnPainel = $SQLPainel->fetch()){
											$painel = $LnPainel['painel'];
											$valorcsp = $LnPainel['valorcsp'];
											
											$block = "N";
											$SQLP = "SELECT nome, url, maxserver FROM painel WHERE id = :id AND block = :block";
											$SQLP = $painel_geral->prepare($SQLP);
											$SQLP->bindParam(':id', $painel, PDO::PARAM_STR);
											$SQLP->bindParam(':block', $block, PDO::PARAM_STR);
											$SQLP->execute();
											$LnP = $SQLP->fetch();
											$nome = $LnP['nome'];
											$UrlPainel = $LnP['url'];
											$MaxPainel = $LnP['maxserver'];
											
											$SServer = VerificarStatusServidor($valorcsp);
											$StatusServer = empty($SServer) ? 0 : $SServer;
											$totalUserServer = VerificarUsoServidor($UrlPainel);
											$percent = intval($totalUserServer/$MaxPainel * 100); 
																						
											if($StatusServer > 0 & $percent <= 99 ){
												$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Online']."\">".$_TRA['Online']."</span>
														   <span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Porcentagem de uso do servidor\">".$percent."%</span>";
											}
											
											elseif($StatusServer > 0 & $percent >= 100 ){
												$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Online']."\">".$_TRA['Online']."</span>
														   <span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\">".$percent."%</span>";
											}											
											else{
												$status = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Offline']."\">".$_TRA['Offline']."</span>
														   <span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Porcentagem de uso do servidor\">".$percent."%</span>";
												
													$MensagemOffline = "".UrlAtual()." ".$_TRA['informa'].": ".$_TRA['oserver']." ".$nome." (".$UrlPainel.") ".$_TRA['ecso'].".";
													$assunto = $_TRA['ServidorOffline'];
													
													
													$SqlStatusServer = "SELECT * FROM status_servidor";
													$SqlStatusServer = $painel_geral->prepare($SqlStatusServer);
													$SqlStatusServer->execute();
													$LnStatusServer = $SqlStatusServer->fetch();
													$EnviarStatus = $LnStatusServer['status'];
													
													if($EnviarStatus == "S"){
														
													$SQLSMS = "SELECT usuario FROM admin";
													$SQLSMS = $painel_user->prepare($SQLSMS);
													$SQLSMS->execute();
													while($LnSMS = $SQLSMS->fetch()){
														
														//Enviar SMS
														$VerificarSMSLibComputador = VerificarSMSLibComputador($LnSMS['usuario']);
														if( ($VerificarSMSLibComputador != 1) && ($VerificarSMSLibComputador != 2) ){
															$celular = $LnStatusServer['celular'];
															EnviarSMS($LnSMS['usuario'], $MensagemOffline, $celular);
														}
														
														//Enviar Email
														$VerificarVerEmail = VerificarVerEmail($LnSMS['usuario']);
														if( ($VerificarVerEmail != 1) && ($VerificarVerEmail != 2) ){
															
															$bloqueado = "N";
															$SQLUser = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
															$SQLUser = $painel_geral->prepare($SQLUser);
															$SQLUser->bindParam(':CadUser', $LnSMS['usuario'], PDO::PARAM_STR);
															$SQLUser->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
															$SQLUser->execute();
															$Total = count($SQLUser->fetchAll());
															
															if($Total > 0){
																	$SQLUser->execute();
																	$LnUser = $SQLUser->fetch();
																	$EnviarEmail = EnviarEmail($LnUser['SMTPSecure'], $LnUser['Host'], $LnUser['Port'], $LnUser['usuario'], $LnUser['senha'], $LnUser['email'], $LnUser['exibicao'], $LnStatusServer['email'], $assunto, $MensagemOffline, NULL);
															}

														}
													}
												}
											}
											
											$ArrayPainel = array($nome, $LnPainel['nome'], $status);
											array_push($_SESSION['ServidorPerfil'], $ArrayPainel);
											
											echo "
                                                <tr>
                                                    <td><center>".$nome."</center></td>
                                                    <td><center>".$LnPainel['nome']."</center></td>
                                                    <td><center>".$status."</center></td>
                                                </tr>
												";
											
											}
											
											echo "
                                            </tbody>
                                  </table>

";

	}
	else{
		echo "<center>".$_TRA['nse']."</center>";
	}
	
	
	
}else{
	echo Redirecionar('login.php');
}	
?>