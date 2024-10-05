<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesRelatorio');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesRelatorio = $VerificarAcesso[0];

if($OpcoesRelatorio == 'S'){

$caduser = empty($_POST['caduser']) ? '' : $_POST['caduser'];
$rev = empty($_POST['rev']) ? '' : $_POST['rev'];
$perfilPost = empty($_POST['perfil']) ? '' : $_POST['perfil'];
$tipo = empty($_POST['tipo']) ? '' : $_POST['tipo'];

$EntreData = empty($_POST['EntreData']) ? '' : $_POST['EntreData'];
$AtivoPost = empty($_POST['Ativo']) ? '' : $_POST['Ativo'];
$VencidoPost = empty($_POST['Vencido']) ? '' : $_POST['Vencido'];
$BloqueadoPost = empty($_POST['Bloqueado']) ? '' : $_POST['Bloqueado'];
$Simplificado = empty($_POST['Simplificado']) ? '' : $_POST['Simplificado'];
$PesquisaEntreData = empty($_POST['PesquisaEntreData']) ? '' : $_POST['PesquisaEntreData'];
$DataAtual = time();
		
if(empty($caduser)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sur'], "danger");
}
elseif(empty($rev)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['edr'], "danger");
}
elseif(empty($perfilPost)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['sup'], "danger");
}
elseif(empty($tipo)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['teuco'], "danger");
}
else{
	
	if($Simplificado == "on"){
		$GerarRelatorio = GerarRelatorio($caduser, $rev, $perfilPost, $tipo, $AtivoPost, $VencidoPost, $BloqueadoPost, $PesquisaEntreData);
	}
	else{
				
		$CadUserRelatorio = ArvoreAdminRev($caduser);
		$CadUserRelatorio[] = $caduser;
		$CadUserRelatorio = array_reverse($CadUserRelatorio);
		
	}
	?>

							<div class="btn-group pull-right" style="padding:0px 0px 15px 0px;">
                                        <button class="btn btn-danger dropdown-toggle" data-toggle="dropdown"><i class="fa fa-bars"></i> <?php echo $_TRA['et']; ?></button>
                                        <ul class="dropdown-menu">
                                            <li><a href="#" onClick ="SalvarPDF();"><img src='img/icons/pdf.png' width="24"/> <?php echo $_TRA['pdf']; ?></a></li>
                                            <li><a href="#" onClick ="SalvarDOC();"><img src='img/icons/word.png' width="24"/> <?php echo $_TRA['word']; ?></a></li>
                                            <li><a href="#" onClick ="SalvarExcel();"><img src='img/icons/xls.png' width="24"/> <?php echo $_TRA['excel']; ?></a></li>
                                            <li><a href="#" onClick ="SalvarPNG();"><img src='img/icons/png.png' width="24"/> <?php echo $_TRA['png']; ?></a></li>
                                            
                                        </ul>
                            </div>


						<?php
						$VerificarTipoSAT = VerificarTipo('SAT');
						if( ($tipo == "SAT") && ($VerificarTipoSAT > 0) || ($tipo == "T") && ($VerificarTipoSAT > 0) ){
						?>
						<div class="panel panel-default">
                                <div class="panel-heading">
                                   <h3 class="panel-title"><?php echo $_TRA['satelite']; ?></h3>                                  
                                </div>
                                
                                <div class="panel-body">
                                    <div class="table-responsive">
                                     
                                     <?php
									 if($Simplificado == "on"){
									 ?>
                                       <table id="Tabela" class="SalvarTabela table table-striped">
                               <thead>
                               		<tr>
                                   		<th>Revendedor</th>
                                   		<th>Data de Vencimento</th>
                                    	<th><?php echo $_TRA['Perfil']; ?></th>
                                    	<th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['vpu']; ?></th>
                                        <th><?php echo $_TRA['Ativos']; ?></th>
                                        <th><?php echo $_TRA['apc']; ?></th>
                                        <th><?php echo $_TRA['vac']; ?></th>
                                        <th><?php echo $_TRA['vacc']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
									
									for($i=0; $i<count($GerarRelatorio); $i++){
																			
									if($GerarRelatorio[$i][0] == "T"){
										$perfil = $_TRA['Todos'];
									}
									else{
										$perfil = SelecionarNomePerfil($GerarRelatorio[$i][0]);
									}
										
										$DataRev = empty($GerarRelatorio[$i][14]) ? "-" : date('d/m/Y', $GerarRelatorio[$i][14]);
						
									echo "	
                                        <tr>
											<td width=\"50\">".$GerarRelatorio[$i][13]."</td>
											<td>".$DataRev."</td>
											<td>".$perfil."</td>
											<td>".$GerarRelatorio[$i][1]."</td>
											<td>".$GerarRelatorio[$i][2]."</td>
											<td>".$GerarRelatorio[$i][3]."</td>
											<td>".$GerarRelatorio[$i][4]."</td>
											<td>".$GerarRelatorio[$i][5]."</td>
											<td>".$GerarRelatorio[$i][6]."</td>
											<td>".$GerarRelatorio[$i][7]."</td>
                                       	 ";
									
								 	echo "</tr>";
									}
								  
										?>
										
                                            </tbody>
                                        </table>
                                        <?php
									    }
										else{
										
                              for($i = 0; $i < count($CadUserRelatorio); $i++){
								  
							  $RevendedorArray = trim($CadUserRelatorio[$i]);
								  
						      $SQLAdminRev = "SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM (SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM admin UNION ALL SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM rev) as newt WHERE newt.usuario = :usuario";
							  $SQLAdminRev = $painel_user->prepare($SQLAdminRev);
						      $SQLAdminRev->bindParam(':usuario', $RevendedorArray, PDO::PARAM_STR);
			                  $SQLAdminRev->execute();
							  $LnAdminRev = $SQLAdminRev->fetch();
								  
							  //Limpa a contagem de perfil
							  $ExpAdRev = explode("[",$LnAdminRev['perfil']);
						      for($i2 = 1; $i2 < count($ExpAdRev); $i2++){
								$PerfArvRev = $ExpAdRev[$i2];
										  
								$ConPerfilRevAdm = str_replace("[","",$PerfArvRev);
								$ConPerfilRevAdm = str_replace("]","",$ConPerfilRevAdm);
								$ConPerfilRevAdm = trim($ConPerfilRevAdm);
								  
								$P{$ConPerfilRevAdm} = 0;
								$Ativo{$ConPerfilRevAdm} = 0;
								$Esgotado{$ConPerfilRevAdm} = 0;
								$Bloqueado{$ConPerfilRevAdm} = 0;
								
								if(empty($TotalUser{$ConPerfilRevAdm})) $TotalUser{$ConPerfilRevAdm} = 0;
								if(empty($AtivoTotal{$ConPerfilRevAdm})) $AtivoTotal{$ConPerfilRevAdm} = 0;
								if(empty($EsgotadoTotal{$ConPerfilRevAdm})) $EsgotadoTotal{$ConPerfilRevAdm} = 0;
								if(empty($BloqueadoTotal{$ConPerfilRevAdm})) $BloqueadoTotal{$ConPerfilRevAdm} = 0;
								
							    if(empty($FinalTotalTotalSAT)) $FinalTotalTotalSAT = 0;
								if(empty($FinalBloqueadoConexaoSAT)) $FinalBloqueadoConexaoSAT = 0;
								if(empty($FinalEsgotadoConexaoSAT)) $FinalEsgotadoConexaoSAT = 0;
								if(empty($FinalAtivoConexaoSAT)) $FinalAtivoConexaoSAT = 0;
						
							 }
								  
							  $ACobrarConexaoSAT = $LnAdminRev['ValorCobrado'];
							  $ACobrarConexaoSAT = number_format($ACobrarConexaoSAT, 2, ',', '');
							  $ACobrarConexaoSAT = VerRepDin()." ".$ACobrarConexaoSAT;
								  
							  $PesquisarEntreDatasSQLAtivo = "";
							  if($AtivoPost == "on"){
								 $PesquisarEntreDatasSQLAtivo = " AND bloqueado = 'N' AND data_premio >= '".$DataAtual."'"; 
							  }
								  
							  $PesquisarEntreDatasSQLVencido = "";
							  if($VencidoPost == "on"){
								 $PesquisarEntreDatasSQLVencido = " AND data_premio < '".$DataAtual."'"; 
							  }
								  
							  $PesquisarEntreDatasSQLBloqueado = "";
							  if($BloqueadoPost == "on"){
								 $PesquisarEntreDatasSQLBloqueado = " AND bloqueado = 'S'"; 
							  }
								  
								
							  $PesquisarEntreDatasSQL = "CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado;
							  if($EntreData == "on"){
								  $DataExplode = explode(" - ",$PesquisaEntreData);
								  $DataInicial = trim($DataExplode[0]);
								  $DataFinal = trim($DataExplode[1]);

								  //Tratamento da Data Inicial
								  $TratarDataInicial = explode("/",$DataInicial);
								  $TratarDataInicialDia = trim($TratarDataInicial[0]);
								  $TratarDataInicialMes = trim($TratarDataInicial[1]);
								  $TratarDataInicialAno = trim($TratarDataInicial[2]);
	
								  $DataInicialOK = strtotime("".$TratarDataInicialAno."-".$TratarDataInicialMes."-".$TratarDataInicialDia."");
	
								  //Tratamento da Data Final
								  $TratarDataFinal = explode("/",$DataFinal);
								  $TratarDataFinalDia = trim($TratarDataFinal[0]);
								  $TratarDataFinalMes = trim($TratarDataFinal[1]);
								  $TratarDataFinalAno = trim($TratarDataFinal[2]);
	
								  $DataFinalOK = strtotime("".$TratarDataFinalAno."-".$TratarDataFinalMes."-".$TratarDataFinalDia."");
	
								  $PesquisarEntreDatasSQL = "CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio > ".$DataInicialOK." AND data_premio < ".$DataFinalOK." OR CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio = ".$DataInicialOK." OR CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio = ".$DataFinalOK;
							  }
								  
							  $SQLUser = "SELECT nome, usuario, bloqueado, data_premio, conexao, perfil, data_cadastro FROM usuario WHERE ".$PesquisarEntreDatasSQL;
							  $SQLUser = $painel_user->prepare($SQLUser);
						      $SQLUser->bindParam(':CadUser', $RevendedorArray, PDO::PARAM_STR);
			                  $SQLUser->execute();
								  
							  if( ($LnAdminRev['CadUser'] == $caduser) || ($LnAdminRev['usuario'] == $caduser) ) {
								  $BodyMarginLeft = "0";
								  $BodyMarginLeftPainel = "75";
							  }
							  else{
								  $BodyMarginLeft = "75";
								  $BodyMarginLeftPainel = "75";
							  }
								  
							  $PerfilArv = $LnAdminRev['perfil'];
								  
                              echo "<div style=\"margin-left: ".$BodyMarginLeft."px;\"><h3 class=\"panel-title\" style=\"color: red; font-weight: bold;\">".ucfirst($RevendedorArray)."</h3> 
                              
                              <table id=\"Tabela\" class=\"SalvarTabela table table-bordered\">
                               <thead>
                               		<tr>
                                   		<th>Nome</th>
                                   		<th>Usuário</th>
										<th>Perfil</th>
										<th>Conexão</th>
                                    	<th>Valor</th>
                                        <th>Criado em</th>
                                        <th>Vencimento</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>";
									
								    $ExisteTabela = 0;
									while($LnUser = $SQLUser->fetch()){
										
										$VerificarTipoPerfil = VerificarTipoPerfil($LnUser['perfil']);
										if(substr_count($VerificarTipoPerfil, "SAT") == 0){
											continue;
										}
										
										if($perfilPost != "T"){
											if(substr_count($LnUser['perfil'], $perfilPost) == 0){
												continue;
											}
										}
										
										$perfil = SelecionarPerfilNome($LnUser['perfil']);
										
										$VariavelSomCon = empty($LnUser['conexao']) ? 1 : $LnUser['conexao'];
										
										//Contar Perfils
										$ContarPerfil = explode("[",$LnUser['perfil']);
									    for($i2 = 1; $i2 < count($ContarPerfil); $i2++){
										   $ConPerfil = str_replace("[","",$ContarPerfil[$i2]);
										   $ConPerfil = str_replace("]","",$ConPerfil);
										   $ConPerfil = trim($ConPerfil);
										   
										   $P{$ConPerfil} += $VariavelSomCon;
										   $TotalUser{$ConPerfil} += $VariavelSomCon;
											
											if($LnUser['bloqueado'] == "S"){
 												$Bloqueado{$ConPerfil} += $VariavelSomCon;
												$BloqueadoTotal{$ConPerfil} += $VariavelSomCon;
											}
											elseif($LnUser['data_premio'] < $DataAtual){
												$Esgotado{$ConPerfil} += $VariavelSomCon;
												$EsgotadoTotal{$ConPerfil} += $VariavelSomCon;
											}
											else{
												$Ativo{$ConPerfil} += $VariavelSomCon;
												$AtivoTotal{$ConPerfil} += $VariavelSomCon;
											}
											
									    }
										
										$FinalTotalTotalSAT += $VariavelSomCon;
											
										if($LnUser['bloqueado'] == "S"){
 											$FinalBloqueadoConexaoSAT += $VariavelSomCon;
										}
										elseif($LnUser['data_premio'] < $DataAtual){
											$FinalEsgotadoConexaoSAT += $VariavelSomCon;
										}
										else{
											$FinalAtivoConexaoSAT += $VariavelSomCon;
										}
										
										if($LnUser['bloqueado'] == "S"){
											$status = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Bloqueado\">Bloqueado</span>";
										}
										elseif($LnUser['data_premio'] < $DataAtual){
											$status = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Esgotado\">Esgotado</span>";
										}
										else{
											$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Ativo\">Ativo</span>";
										}
										
										$ExisteTabela = 1;
                                        echo "<tr>
											<td>".$LnUser['nome']."</td>
											<td>".$LnUser['usuario']."</td>
											<td>".$perfil."</td>
											<td>".$LnUser['conexao']."</td>
											<td>".$ACobrarConexaoSAT."</td>
											<td>".date("d/m/Y",strtotime($LnUser['data_cadastro']))."</td>
											<td>".date("d/m/Y",$LnUser['data_premio'])."</td>
											<td>".$status."</td>
                                       	 </tr>";
									}
								  
								  if($ExisteTabela == 0){
									  echo "<tr><td colspan=\"8\">Nada encontrado!</td></tr>";
								  }
								  
										
                                      echo "</tbody>
                                        </table>
										<br>
										
										<div style=\"margin-left: ".$BodyMarginLeftPainel."px;\">
										
											<div style=\"width: 500px;\"><table id=\"Tabela\" class=\"SalvarTabela table table-bordered\">
                               					<thead>
                               						<tr>
                                   						<th></th>
														<th>Total</th>
														<th>Ativo</th>
                                   						<th>Esgotado</th>
														<th>Bloqueado</th>
                                    				</tr>
												</thead>
                                				<tbody>";
												
								      $ExisteTabelaRel = 0;
									  $ExpPerfilArv = explode("[",$PerfilArv);
									  for($is = 1; $is < count($ExpPerfilArv); $is++){
										  $PerfArv = "[".$ExpPerfilArv[$is];
										  
										  $VerificarTipoPerfilInd = VerificarTipoPerfilInd($PerfArv);
										  if($VerificarTipoPerfilInd != "SAT"){
											  continue;
										  }
										  
										  if($perfilPost != "T"){
											if($PerfArv != $perfilPost){
												continue;
											}
										  }
										  
										  $SelecionarPerfilNome = SelecionarPerfilNome($PerfArv);
										  
										  $ConPerfilRev = str_replace("[","",$PerfArv);
										  $ConPerfilRev = str_replace("]","",$ConPerfilRev);
										  $ConPerfilRev = trim($ConPerfilRev);
										  			
										  			$ExisteTabelaRel = 1;
													echo "<tr>
														<td>".trim(str_replace(";","",$SelecionarPerfilNome))."</td>
														<td>".$P{$ConPerfilRev}."</td>
														<td>".$Ativo{$ConPerfilRev}."</td>
														<td>".$Esgotado{$ConPerfilRev}."</td>
														<td>".$Bloqueado{$ConPerfilRev}."</td>
													</tr>";
									  }
								  
								  				if($ExisteTabelaRel == 0){
									  				echo "<tr><td colspan=\"5\">Nada encontrado!</td></tr>";
								  				}
													
												echo "</tbody>
											</table>
											</div>
										</div>
										
										
										
										</div>
									";
											
										}
									}
										?>
                                                                                      
                                    </div>
                                </div>
                            </div>
                            
                            <?php
							}
							
							$VerificarTipoCAB = VerificarTipo('CAB');
							if( ($tipo == "CAB") && ($VerificarTipoCAB > 0) || ($tipo == "T") && ($VerificarTipoCAB > 0) ){
							?>
                            
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                   <h3 class="panel-title"><?php echo $_TRA['cabo']; ?></h3>                                  
                                </div>
                                
                                <div class="panel-body">
                                    <div class="table-responsive">
                                     
                                     <?php
									 if($Simplificado == "on"){
									 ?>
                                     <table id="Tabela" class="SalvarTabela table table-striped">
                               <thead>
                               		<tr>
                                   		<th>Revendedor</th>
                                   		<th>Data de Vencimento</th>
                                    	<th><?php echo $_TRA['Perfil']; ?></th>
                                    	<th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['vpu']; ?></th>
                                        <th><?php echo $_TRA['Ativos']; ?></th>
                                        <th><?php echo $_TRA['apc']; ?></th>
                                        <th><?php echo $_TRA['vac']; ?></th>
                                        <th><?php echo $_TRA['vacc']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
									
									for($i=0; $i<count($GerarRelatorio); $i++){
									
									if($GerarRelatorio[$i][0] == "T"){
										$perfil = $_TRA['Todos'];
									}
									else{
										$perfil = SelecionarNomePerfil($GerarRelatorio[$i][0]);
									}
										
									$DataRev = empty($GerarRelatorio[$i][14]) ? "-" : date('d/m/Y', $GerarRelatorio[$i][14]);
									
									echo "	
                                        <tr>
											<td width=\"50\">".$GerarRelatorio[$i][13]."</td>
											<td>".$DataRev."</td>
											<td>".$perfil."</td>
											<td>".$GerarRelatorio[$i][1]."</td>
											<td>".$GerarRelatorio[$i][2]."</td>
											<td>".$GerarRelatorio[$i][8]."</td>
											<td>".$GerarRelatorio[$i][9]."</td>
											<td>".$GerarRelatorio[$i][10]."</td>
											<td>".$GerarRelatorio[$i][11]."</td>
											<td>".$GerarRelatorio[$i][12]."</td>
                                       	 ";
									
								 	echo "</tr>";
									}
										 
								  
										?>
										
                                            </tbody>
                                        </table>
                                        <?php
									    }
								else{
										
                              for($i = 0; $i < count($CadUserRelatorio); $i++){
								  
							  $RevendedorArray = trim($CadUserRelatorio[$i]);
								  
						      $SQLAdminRev = "SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM (SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM admin UNION ALL SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM rev) as newt WHERE newt.usuario = :usuario";
							  $SQLAdminRev = $painel_user->prepare($SQLAdminRev);
						      $SQLAdminRev->bindParam(':usuario', $RevendedorArray, PDO::PARAM_STR);
			                  $SQLAdminRev->execute();
							  $LnAdminRev = $SQLAdminRev->fetch();
								  
							  //Limpa a contagem de perfil
							  $ExpAdRev = explode("[",$LnAdminRev['perfil']);
						      for($i2 = 1; $i2 < count($ExpAdRev); $i2++){
								$PerfArvRev = $ExpAdRev[$i2];
										  
								$ConPerfilRevAdm = str_replace("[","",$PerfArvRev);
								$ConPerfilRevAdm = str_replace("]","",$ConPerfilRevAdm);
								$ConPerfilRevAdm = trim($ConPerfilRevAdm);
								  
								$P2{$ConPerfilRevAdm} = 0;
								$Ativo2{$ConPerfilRevAdm} = 0;
								$Esgotado2{$ConPerfilRevAdm} = 0;
								$Bloqueado2{$ConPerfilRevAdm} = 0;
								
								if(empty($TotalUser2{$ConPerfilRevAdm})) $TotalUser2{$ConPerfilRevAdm} = 0;
								if(empty($AtivoTotal2{$ConPerfilRevAdm})) $AtivoTotal2{$ConPerfilRevAdm} = 0;
								if(empty($EsgotadoTotal2{$ConPerfilRevAdm})) $EsgotadoTotal2{$ConPerfilRevAdm} = 0;
								if(empty($BloqueadoTotal2{$ConPerfilRevAdm})) $BloqueadoTotal2{$ConPerfilRevAdm} = 0;
								
								if(empty($FinalTotalTotalCAB)) $FinalTotalTotalCAB = 0;
								if(empty($FinalBloqueadoConexaoCAB)) $FinalBloqueadoConexaoCAB = 0;
								if(empty($FinalEsgotadoConexaoCAB)) $FinalEsgotadoConexaoCAB = 0;
								if(empty($FinalAtivoConexaoCAB)) $FinalAtivoConexaoCAB = 0;
						
							 }
								  
							  $ACobrarConexaoSAT = $LnAdminRev['ValorCobradoCabo'];
							  $ACobrarConexaoSAT = number_format($ACobrarConexaoSAT, 2, ',', '');
							  $ACobrarConexaoSAT = VerRepDin()." ".$ACobrarConexaoSAT;
								  
							  $PesquisarEntreDatasSQLAtivo = "";
							  if($AtivoPost == "on"){
								 $PesquisarEntreDatasSQLAtivo = " AND bloqueado = 'N' AND data_premio >= '".$DataAtual."'"; 
							  }
								  
							  $PesquisarEntreDatasSQLVencido = "";
							  if($VencidoPost == "on"){
								 $PesquisarEntreDatasSQLVencido = " AND data_premio < '".$DataAtual."'"; 
							  }
								  
							  $PesquisarEntreDatasSQLBloqueado = "";
							  if($BloqueadoPost == "on"){
								 $PesquisarEntreDatasSQLBloqueado = " AND bloqueado = 'S'"; 
							  }
								  
								
							  $PesquisarEntreDatasSQL = "CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado;
							  if($EntreData == "on"){
								  $DataExplode = explode(" - ",$PesquisaEntreData);
								  $DataInicial = trim($DataExplode[0]);
								  $DataFinal = trim($DataExplode[1]);

								  //Tratamento da Data Inicial
								  $TratarDataInicial = explode("/",$DataInicial);
								  $TratarDataInicialDia = trim($TratarDataInicial[0]);
								  $TratarDataInicialMes = trim($TratarDataInicial[1]);
								  $TratarDataInicialAno = trim($TratarDataInicial[2]);
	
								  $DataInicialOK = strtotime("".$TratarDataInicialAno."-".$TratarDataInicialMes."-".$TratarDataInicialDia."");
	
								  //Tratamento da Data Final
								  $TratarDataFinal = explode("/",$DataFinal);
								  $TratarDataFinalDia = trim($TratarDataFinal[0]);
								  $TratarDataFinalMes = trim($TratarDataFinal[1]);
								  $TratarDataFinalAno = trim($TratarDataFinal[2]);
	
								  $DataFinalOK = strtotime("".$TratarDataFinalAno."-".$TratarDataFinalMes."-".$TratarDataFinalDia."");
	
								  $PesquisarEntreDatasSQL = "CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio > ".$DataInicialOK." AND data_premio < ".$DataFinalOK." OR CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio = ".$DataInicialOK." OR CadUser = :CadUser".$PesquisarEntreDatasSQLAtivo.$PesquisarEntreDatasSQLVencido.$PesquisarEntreDatasSQLBloqueado." AND data_premio = ".$DataFinalOK;
							  }
								  
							  $SQLUser = "SELECT nome, usuario, bloqueado, data_premio, conexao, perfil, data_cadastro FROM usuario WHERE ".$PesquisarEntreDatasSQL;
							  $SQLUser = $painel_user->prepare($SQLUser);
						      $SQLUser->bindParam(':CadUser', $RevendedorArray, PDO::PARAM_STR);
			                  $SQLUser->execute();
								  
							  if( ($LnAdminRev['CadUser'] == $caduser) || ($LnAdminRev['usuario'] == $caduser) ) {
								  $BodyMarginLeft = "0";
								  $BodyMarginLeftPainel = "75";
							  }
							  else{
								  $BodyMarginLeft = "75";
								  $BodyMarginLeftPainel = "75";
							  }
								  
							  $PerfilArv = $LnAdminRev['perfil'];
								  
                              echo "<div style=\"margin-left: ".$BodyMarginLeft."px;\"><h3 class=\"panel-title\" style=\"color: red; font-weight: bold;\">".ucfirst($RevendedorArray)."</h3> 
                              
                              <table id=\"Tabela\" class=\"SalvarTabela table table-bordered\">
                               <thead>
                               		<tr>
                                   		<th>Nome</th>
                                   		<th>Usuário</th>
										<th>Perfil</th>
										<th>Conexão</th>
                                    	<th>Valor</th>
                                        <th>Criado em</th>
                                        <th>Vencimento</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>";
									
								    $ExisteTabela = 0;
									while($LnUser = $SQLUser->fetch()){
										
										
										$VerificarTipoPerfil = VerificarTipoPerfil($LnUser['perfil']);
										if(substr_count($VerificarTipoPerfil, "CAB") == 0){
											continue;
										}
										
										if($perfilPost != "T"){
											if(substr_count($LnUser['perfil'], $perfilPost) == 0){
												continue;
											}
										}
										
										$perfil = SelecionarPerfilNome($LnUser['perfil']);
										
										$VariavelSomCon = empty($LnUser['conexao']) ? 1 : $LnUser['conexao'];
										
										//Contar Perfils
										$ContarPerfil = explode("[",$LnUser['perfil']);
									    for($i2 = 1; $i2 < count($ContarPerfil); $i2++){
										   $ConPerfil = str_replace("[","",$ContarPerfil[$i2]);
										   $ConPerfil = str_replace("]","",$ConPerfil);
										   $ConPerfil = trim($ConPerfil);
										   
										   $P2{$ConPerfil} += $VariavelSomCon;
										   $TotalUser2{$ConPerfil} += $VariavelSomCon;
											
											if($LnUser['bloqueado'] == "S"){
 												$Bloqueado2{$ConPerfil} += $VariavelSomCon;
												$BloqueadoTotal2{$ConPerfil} += $VariavelSomCon;
											}
											elseif($LnUser['data_premio'] < $DataAtual){
												$Esgotado2{$ConPerfil} += $VariavelSomCon;
												$EsgotadoTotal2{$ConPerfil} += $VariavelSomCon;
											}
											else{
												$Ativo2{$ConPerfil} += $VariavelSomCon;
												$AtivoTotal2{$ConPerfil} += $VariavelSomCon;
											}
											
									    }
										
										$FinalTotalTotalCAB += $VariavelSomCon;
										
										if($LnUser['bloqueado'] == "S"){
 											$FinalBloqueadoConexaoCAB += $VariavelSomCon;
										}
										elseif($LnUser['data_premio'] < $DataAtual){
											$FinalEsgotadoConexaoCAB += $VariavelSomCon;
										}
										else{
											$FinalAtivoConexaoCAB += $VariavelSomCon;
										}
										
										
										if($LnUser['bloqueado'] == "S"){
											$status = "<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Bloqueado\">Bloqueado</span>";
										}
										elseif($LnUser['data_premio'] < $DataAtual){
											$status = "<span class=\"pointer label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Esgotado\">Esgotado</span>";
										}
										else{
											$status = "<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"Ativo\">Ativo</span>";
										}
										
										$ExisteTabela = 1;
                                        echo "<tr>
											<td>".$LnUser['nome']."</td>
											<td>".$LnUser['usuario']."</td>
											<td>".$perfil."</td>
											<td>".$LnUser['conexao']."</td>
											<td>".$ACobrarConexaoSAT."</td>
											<td>".date("d/m/Y",strtotime($LnUser['data_cadastro']))."</td>
											<td>".date("d/m/Y",$LnUser['data_premio'])."</td>
											<td>".$status."</td>
                                       	 </tr>";
									}
								  
								  
								  if($ExisteTabela == 0){
									  echo "<tr><td colspan=\"8\">Nada encontrado!</td></tr>";
								  }
										
                                      echo "</tbody>
                                        </table>
										<br>
										
										<div style=\"margin-left: ".$BodyMarginLeftPainel."px;\">
										
											<div style=\"width: 500px;\"><table id=\"Tabela\" class=\"SalvarTabela table table-bordered\">
                               					<thead>
                               						<tr>
                                   						<th></th>
														<th>Total</th>
														<th>Ativo</th>
                                   						<th>Esgotado</th>
														<th>Bloqueado</th>
                                    				</tr>
												</thead>
                                				<tbody>";
												
								  	  $ExisteTabelaRel = 0;
									  $ExpPerfilArv = explode("[",$PerfilArv);
									  for($is = 1; $is < count($ExpPerfilArv); $is++){
										  $PerfArv = "[".$ExpPerfilArv[$is];
										  
										  $VerificarTipoPerfilInd = VerificarTipoPerfilInd($PerfArv);
										  if($VerificarTipoPerfilInd != "CAB"){
											  continue;
										  }
										  
										  if($perfilPost != "T"){
											if($PerfArv != $perfilPost){
												continue;
											}
										  }
										  
										  $SelecionarPerfilNome = SelecionarPerfilNome($PerfArv);
										  
										  $ConPerfilRev = str_replace("[","",$PerfArv);
										  $ConPerfilRev = str_replace("]","",$ConPerfilRev);
										  $ConPerfilRev = trim($ConPerfilRev);
										  			
										  			$ExisteTabelaRel = 1;
													echo "<tr>
														<td>".trim(str_replace(";","",$SelecionarPerfilNome))."</td>
														<td>".$P2{$ConPerfilRev}."</td>
														<td>".$Ativo2{$ConPerfilRev}."</td>
														<td>".$Esgotado2{$ConPerfilRev}."</td>
														<td>".$Bloqueado2{$ConPerfilRev}."</td>
													</tr>";
									  }
								  
								  				if($ExisteTabelaRel == 0){
									  				echo "<tr><td colspan=\"5\">Nada encontrado!</td></tr>";
								  				}
													
												echo "</tbody>
											</table>
											</div>
										</div>
										
										
										
										</div>
									";
											
										}
									}
										?>
                                                        
                                    </div>
                                </div>
                            </div>
                            
                            <?php
							}
							if($Simplificado != "on"){
							?>
                            
                            <div class="panel panel-default">
                                <div class="panel-heading">
                                   <h3 class="panel-title">Relatório Final</h3>                                  
                                </div>
                                
                                <div class="panel-body">
                                    <div class="table-responsive">
                                     
                                     <?php
											$SQLAdminRev = "SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM (SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM admin UNION ALL SELECT CadUser, usuario, ValorCobrado, ValorCobradoCabo, perfil FROM rev) as newt WHERE newt.usuario = :usuario";
							  				$SQLAdminRev = $painel_user->prepare($SQLAdminRev);
						      				$SQLAdminRev->bindParam(':usuario', $caduser, PDO::PARAM_STR);
			                  				$SQLAdminRev->execute();
							  				$LnAdminRev = $SQLAdminRev->fetch();
											
											$PerfilArv = $LnAdminRev['perfil'];
											$ValorCobradoArv = $LnAdminRev['ValorCobrado'];
											$ValorCobradoArvCab = $LnAdminRev['ValorCobradoCabo'];
								
											$TotalAtivosSomarFinalSat = 0;
										    $TotalAtivosSomarFinalCab = 0;
						
											echo "
											<div style=\"width: 500px;\">
											<table id=\"Tabela\" class=\"SalvarTabela table table-bordered\">
                               					<thead>
                               						<tr>
                                   						<th></th>
														<th>Total</th>
														<th>Ativos</th>
                                   						<th>Esgotados</th>
														<th>Bloqueados</th>
                                    				</tr>
												</thead>
                                				<tbody>";
									  
									  $TotalAPagarSat = 0;
									  $ExpPerfilArv = explode("[",$PerfilArv);
									  for($i3 = 1; $i3 < count($ExpPerfilArv); $i3++){
										  $PerfArv = "[".$ExpPerfilArv[$i3];
										  
										if($perfilPost != "T"){
											if($PerfArv != $perfilPost){
												continue;
											}
										}
										  
										  $SelecionarPerfilNome = SelecionarPerfilNome($PerfArv);
										  
										  $ConPerfilRev = str_replace("[","",$PerfArv);
										  $ConPerfilRev = str_replace("]","",$ConPerfilRev);
										  $ConPerfilRev = trim($ConPerfilRev);
										  
										  $TotalAtivosSomarFinalSat += $AtivoTotal{$ConPerfilRev};
										  $TotalAtivosSomarFinalCab += $AtivoTotal2{$ConPerfilRev};
										  
										  $VerificarTipoPerfilInd = VerificarTipoPerfilInd($PerfArv);
										  if($VerificarTipoPerfilInd == "SAT"){
											  
											$TotalTotalSat += $TotalUser{$ConPerfilRev};
										  	$TotalAtivosSat += $AtivoTotal{$ConPerfilRev};
										  	$TotalEsgotadosSat += $EsgotadoTotal{$ConPerfilRev};
										  	$TotalBloqueadosSat += $BloqueadoTotal{$ConPerfilRev};
											  
												echo "<tr>
														<td>".trim(str_replace(";","",$SelecionarPerfilNome))."</td>
														<td>".$TotalUser{$ConPerfilRev}."</td>
														<td>".$AtivoTotal{$ConPerfilRev}."</td>
														<td>".$EsgotadoTotal{$ConPerfilRev}."</td>
														<td>".$BloqueadoTotal{$ConPerfilRev}."</td>
													</tr>";
										  }
										  else{
											  
											$TotalTotalSat += $TotalUser2{$ConPerfilRev};
										  	$TotalAtivosSat += $AtivoTotal2{$ConPerfilRev};
										  	$TotalEsgotadosSat += $EsgotadoTotal2{$ConPerfilRev};
										  	$TotalBloqueadosSat += $BloqueadoTotal2{$ConPerfilRev};
											  
											  echo "<tr>
														<td>".trim(str_replace(";","",$SelecionarPerfilNome))."</td>
														<td>".$TotalUser2{$ConPerfilRev}."</td>
														<td>".$AtivoTotal2{$ConPerfilRev}."</td>
														<td>".$EsgotadoTotal2{$ConPerfilRev}."</td>
														<td>".$BloqueadoTotal2{$ConPerfilRev}."</td>
													</tr>";
										  }
									  }

									   $TotalValorFinal = ($FinalAtivoConexaoSAT * $ValorCobradoArv) + ($FinalAtivoConexaoCAB * $ValorCobradoArvCab);
								       $ACobrarTotalAtivosFinal = number_format($TotalValorFinal, 2, ',', '');
									   $ACobrarTotalAtivosFinal = VerRepDin()." ".$ACobrarTotalAtivosFinal;
								       
								       $FinalTotalTotal = $FinalTotalTotalSAT + $FinalTotalTotalCAB;
								       $FinalBloqueadoConexao = $FinalBloqueadoConexaoSAT + $FinalBloqueadoConexaoCAB;
								       $FinalEsgotadoConexao = $FinalEsgotadoConexaoSAT + $FinalEsgotadoConexaoCAB;
								       $FinalAtivoConexao = $FinalAtivoConexaoSAT + $FinalAtivoConexaoCAB;
													
												echo "
													<tr>
														<td>TOTAL USER</td>
														<td>".$FinalTotalTotal."</td>
														<td>".$FinalAtivoConexao."</td>
														<td>".$FinalEsgotadoConexao."</td>
														<td>".$FinalBloqueadoConexao."</td>
													</tr>
														
													<tr>
														<td colspan=\"5\">
														<span style=\"font-weight: bold; font-size: 22px;\">Total à Pagar:</span> <span style=\"color: red; font-weight: bold; font-size: 22px; float: right;\">".$ACobrarTotalAtivosFinal."</span>
														</td>
													</tr>
												</tbody>
											</table>
											</div>
											
											";
										?>
                                                        
                                    </div>
                                </div> 
                            </div>
                            
                            <?php
							}	
							?>
                            
        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>
                                    
        <script type="text/javascript" src="js/plugins/tableexport/libs/FileSaver/FileSaver.min.js"></script>
        <script type="text/javascript" src="js/plugins/tableexport/libs/jsPDF/jspdf.min.js"></script>
        <script type="text/javascript" src="js/plugins/tableexport/libs/jsPDF-AutoTable/jspdf.plugin.autotable.js"></script>
        <script type="text/javascript" src="js/plugins/tableexport/libs/html2canvas/html2canvas.min.js"></script>
        <script type="text/javascript" src="js/plugins/tableexport/tableExport.min.js"></script>
        <script type="text/javascript" src="js/plugins/tableexport/tableExport.js"></script>
        
        <script type="text/javascript" src="js/plugins.js"></script>
        
        <script type="text/javascript">
        function SalvarPDF(){
			
					$('.SalvarTabela').tableExport({
						fileName: '<?php echo $caduser; ?>',
                        type: 'pdf',
						escape: 'false',
                        jspdf: {format: 'bestfit',
                                margins: {left:20, right:10, top:20, bottom:20},
								autotable: {styles: {fontSize: '14'},
											tableWidth: 'wrap'
										   }
                               }
                    });
					
		}
		
	    function SalvarDOC(){
			$('.SalvarTabela').tableExport({
				fileName: '<?php echo $caduser; ?>',
				type: 'doc',
				escape: 'false'
				})			
		}
		
		function SalvarExcel(){
			$('.SalvarTabela').tableExport({
				fileName: '<?php echo $caduser; ?>',
				type: 'xls',
				escape: 'false'
				})			
		}
		
		function SalvarPNG(){
			$('.SalvarTabela').tableExport({
				fileName: '<?php echo $caduser; ?>',
				type: 'png',
				escape: 'false'
				})			
		}
		</script>



<?php
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>