<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){

$UserOnline = InfoUser(2);
$AcessoOnline = InfoUser(3);
$bloqueado = "N";

$SQLSMS = "SELECT creditos, valor FROM sms WHERE CadUser = :CadUser AND bloqueado = :bloqueado";
$SQLSMS = $painel_geral->prepare($SQLSMS);
$SQLSMS->bindParam(':CadUser', $UserOnline, PDO::PARAM_STR);
$SQLSMS->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
$SQLSMS->execute();
$LnSMS = $SQLSMS->fetch();
$saldoapi = $LnSMS['creditos'];

//Teste
$Coluna_10 = array('TesteVisualizar');
$VerificarAcesso_10 = VerificarAcesso('teste', $Coluna_10);
$TesteVisualizar = $VerificarAcesso_10[0];

//Url de Teste
$ColunaUrldeTeste = array('RevUrldeTeste');
$VerificarAcessoUrldeTeste = VerificarAcesso('rev', $ColunaUrldeTeste);
$RevUrldeTeste = $VerificarAcessoUrldeTeste[0];

//Status do Servidor
$ColunaStatusServer = array('OpcoesStatusServer');
$VerificarStatusServer = VerificarAcesso('opcoes', $ColunaStatusServer);
$AdminStatusServer = $VerificarStatusServer[0];
?>

				<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                    <li class="active"><?php echo $_TRA['inicio']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->


<div class="page-content-wrap">

						<?php
						if( ($AcessoOnline == 1) || ($AcessoOnline == 2) ){
						?>

<div class="row">

						<div class="col-md-3">
                            <!-- START WIDGET MESSAGES -->
                            <div class="pointer widget widget-default widget-item-icon" onclick="location.href='index.php?p=usuario&s=1';">
                                <div class="widget-item-left">
                                    <span class="fa fa-user"></span>
                                </div>
                                <div class="widget-data">
                                    <div class="widget-int num-count CountAtivos">
                                    <?php
									$InicioAtivo = empty($_SESSION['InicioContarAtivo']) ? 0 : $_SESSION['InicioContarAtivo'];
									$InicioAtivoS = $InicioAtivo > 1 ? $_TRA['Ativos'] : $_TRA['Ativo'];
									echo $InicioAtivo;
									?>
                                    </div>
                                    <div class="widget-title CountAtivosS" style="font-size:12px;"><?php echo $InicioAtivoS; ?></div>
                                </div>
                            </div>
                            <!-- END WIDGET MESSAGES -->
                        </div>

                        <div class="col-md-3">
                            <!-- START WIDGET MESSAGES -->
                            <div class="pointer widget widget-default widget-item-icon" onclick="location.href='index.php?p=usuario&s=2';">
                                <div class="widget-item-left">
                                    <span class="fa fa-user-times"></span>
                                </div>
                                <div class="widget-data">
                                    <div class="widget-int num-count CountEsgotados">
                                    <?php
									$InicioEsgotado = empty($_SESSION['InicioContarEsgotado']) ? 0 : $_SESSION['InicioContarEsgotado'];
									$InicioEsgotadoS = $InicioEsgotado > 1 ? $_TRA['Esgotados'] : $_TRA['Esgotado'];
									echo $InicioEsgotado;
									?>
                                    </div>
                                    <div class="widget-title CountEsgotadosS" style="font-size:12px;"><?php echo $InicioEsgotadoS; ?></div>
                                </div>
                            </div>
                            <!-- END WIDGET MESSAGES -->
                        </div>

                        <div class="col-md-3">
                            <!-- START WIDGET MESSAGES -->
                            <div class="pointer widget widget-default widget-item-icon" onclick="location.href='index.php?p=usuario&s=3';">
                                <div class="widget-item-left">
                                    <span class="fa fa-user-times"></span>
                                </div>
                                <div class="widget-data">
                                    <div class="widget-int num-count CountBloqueados">
                                    <?php
									$InicioBloqueado = empty($_SESSION['InicioContarBloqueado']) ? 0 : $_SESSION['InicioContarBloqueado'];
									$InicioBloqueadoS = $InicioBloqueado > 1 ? $_TRA['Bloqueados'] : $_TRA['Bloqueado'];
									echo $InicioBloqueado;
									?>
                                    </div>
                                    <div class="widget-title CountBloqueadosS" style="font-size:12px;"><?php echo $InicioBloqueadoS; ?></div>
                                </div>
                            </div>
                            <!-- END WIDGET MESSAGES -->
                        </div>

                        <div class="col-md-3">
                            <!-- START WIDGET MESSAGES -->
                            <div class="pointer widget widget-default widget-item-icon" onclick="location.href='index.php?p=teste&s=1';">
                                <div class="widget-item-left">
                                    <span class="fa fa-user"></span>
                                </div>
                                <div class="widget-data">
                                    <div class="widget-int num-count CountTestes">
                                    <?php
									$InicioTeste = empty($_SESSION['InicioContarTeste']) ? 0 : $_SESSION['InicioContarTeste'];
									$InicioTesteS = $InicioTeste > 1 ? $_TRA['tas'] : $_TRA['ta'];
									echo $InicioTeste;
									?>
                                    </div>
                                    <div class="widget-title CountTestesS" style="font-size:12px;"><?php echo $InicioTesteS; ?></div>
                                </div>
                            </div>
                            <!-- END WIDGET MESSAGES -->
                        </div>
						
							<div class="col-md-3">
								<!-- START WIDGET SALDO SMS -->
								<div class="pointer widget widget-default widget-item-icon">
									<div class="widget-item-left">
										<span class="fa fa-usd"></span>
									</div>
									<div class="widget-data">
										<div class="widget-int">
										<?php
										if ($saldoapi > 0) {
											
											echo number_format($saldoapi,2,",",".");
											
										}else{
										echo "0	";
										}
										?>
										</div>
										<div class="widget-title" style="font-size:12px;">SALDO API</div>
									</div>
								</div>
								<!-- END WIDGET MESSAGES -->
							</div>
						
						<div class="col-md-6" style="height: auto; width:100%;">
                        <div class="panel panel-default" style="height: auto;">
                                <div class="panel-heading">
                                    <h3 class="panel-title">Informação importante!</h3>
                                </div>
                                <div class="panel-body" style="height: auto;">
								<span id="info" style="height: auto;">
								<?php include 'noticias/ler.php'; ?>
								
								</span>


								</div>
								 </div>

                        </div>


                         </div>

                         <?php
						  }
						 ?>



                        <div class="row">

                        <?php
						if( ($TesteVisualizar == "S") && ($RevUrldeTeste == "S") ){
						?>
                        <div class="col-md-6">
                        <?php

                        $SQLUrlT = "SELECT status, tempo, cemail, email FROM urlteste WHERE CadUser = :CadUser";
						$SQLUrlT = $painel_geral->prepare($SQLUrlT);
						$SQLUrlT->bindParam(':CadUser', $UserOnline, PDO::PARAM_STR);
						$SQLUrlT->execute();
						$TotalUrlT = count($SQLUrlT->fetchAll());

                        echo "<div class=\"panel panel-default\">
                                <div class=\"panel-heading\">
                                    <h3 class=\"panel-title\">".$_TRA['udt']."</h3>
                                </div>
                                <div class=\"panel-body\">";

								if($TotalUrlT > 0){
									$UrlTeste = UrlTeste(1);
									echo "<div class=\"col-md-9\"><input type=\"text\" class=\"form-control\" value=\"".$UrlTeste."\"></div>";
									echo "<div class=\"col-md-3\"><a target=\"_blank\" href=\"".$UrlTeste."\" class=\"btn btn-default\"><i class=\"fa fa-link\"></i> ".ucfirst($_TRA['caqui'])."</a></div>";
								}
								else{
									echo $_TRA['tncpccec'];
								}

                                echo "</div>
                                <div class=\"panel-footer\">";

								$ColorUrl = $TotalUrlT > 0 ? "info" : "danger";

                                    echo "<a class=\"btn btn-".$ColorUrl." pull-right\" Onclick=\"ConfigTeste()\">".$_TRA['config']."</a>";

                                echo "</div>
                            </div>";

                         ?>

                        </div>
                        <?php
						}
						else{

								echo "<div class=\"col-md-6\">

 							 <div class=\"panel panel-default\">
                                 <div class=\"panel-heading\">
                                     <h3 class=\"panel-title\">".$_TRA['SBV']."</h3>
                                 </div>
                                 <div class=\"panel-body\">

 								<div class=\"col-md-12\">

 								".$_TRA['adpvprsp']."

 								</div>

 								</div>";

              echo "</div></div>";


						}
						?>




                        <div class="col-md-6">
                        <?php

                        echo "<div class=\"panel panel-default\">
                                <div class=\"panel-heading\">
                                    <h3 class=\"panel-title\">".$_TRA['sdc']."</h3>
                                </div>
                                <div class=\"panel-body\">


								<span id=\"StatusVer\">".$_TRA['cevspvoeadsc']."</span>


								</div>
                                <div class=\"panel-footer\">";


                                    echo "<a class=\"btn btn-primary pull-right\" Onclick=\"VerificarStatus()\">".$_TRA['vs']."</a>";

                                echo "</div>
                            </div>";

                         ?>

                        </div>

                    </div>




                    <div class="row" style="height: auto;">


					<div class="col-md-6" style="height: auto;">
                        <?php

						$OperadoraPerfil = empty($_SESSION['OperadoraPerfil']) ? "" : $_SESSION['OperadoraPerfil'];

                        echo "<div class=\"panel panel-default StatusBodyOP\" style=\"height: auto;\">
                                <div class=\"panel-heading\">
                                    <h3 class=\"panel-title\">".$_TRA['io']."</h3>
                                </div>
                                <div class=\"panel-body\" style=\"height: auto;\">


								<span id=\"StatusOperadora\" style=\"height: auto;\">";

								if(!empty($OperadoraPerfil)){
								echo "<table class=\"table table-striped\">
                                            <thead>
                                                <tr>
                                                    <th><center>".$_TRA['Operadora']."</center></th>
                                                    <th><center>".$_TRA['Url']."</center></th>
                                                    <th><center>".$_TRA['Porta']."</center></th>
                                                </tr>
                                            </thead>
                                            <tbody>";

												for($i = 0; $i < count($OperadoraPerfil); $i++){

												$nome = $OperadoraPerfil[$i][0];
												$url = $OperadoraPerfil[$i][1];
												$porta = $OperadoraPerfil[$i][2];

												echo "
                                                <tr>
                                                    <td><center>".$nome."</center></td>
                                                    <td><center>".$url."</center></td>
                                                    <td><center>".$porta."</center></td>
                                                </tr>
												";
												}

											echo "
                                            </tbody>
                                  </table>";
								}
								else{
									echo "<center>".$_TRA['co']."</center>";
								}

								echo "</span>


								</div>
								 <div class=\"panel-footer\">
								<a class=\"btn btn-primary pull-right\" Onclick=\"VerificarOperadora()\">".$_TRA['atualizar']."</a>
                               </div></div>";

                         ?>

                        </div>

                        <div class="col-md-6" style="height: auto;">

                        <?php

						$ServidorPerfil = empty($_SESSION['ServidorPerfil']) ? "" : $_SESSION['ServidorPerfil'];

						 echo "<div class=\"panel panel-default StatusBodyServer\" style=\"height: auto;\">
                                <div class=\"panel-heading\">
                                    <h3 class=\"panel-title\">".$_TRA['sds']."</h3>
                                </div>
                                <div class=\"panel-body\" style=\"height: auto;\">


								<span id=\"StatusServidor\" style=\"height: auto;\">";

								if(!empty($ServidorPerfil)){
								echo "<table class=\"table table-striped\">
                                            <thead>
                                                <tr>
                                                    <th><center>".$_TRA['Servidor']."</center></th>
                                                    <th><center>".$_TRA['Operadora']."</center></th>
                                                    <th><center>".$_TRA['Status']."</center></th>
                                                </tr>
                                            </thead>
                                            <tbody>";

												for($i = 0; $i < count($ServidorPerfil); $i++){

												$NomeServer = $ServidorPerfil[$i][0];
												$NomePainel = $ServidorPerfil[$i][1];
												$Status = $ServidorPerfil[$i][2];

												echo "
                                                <tr>
                                                    <td><center>".$NomeServer."</center></td>
                                                    <td><center>".$NomePainel."</center></td>
                                                    <td><center>".$Status."</center></td>
                                                </tr>
												";
												}

											echo "
                                            </tbody>
                                  </table>";
								}
								else{
									echo "<center>".$_TRA['csds']."</center>";
								}

								echo "</span>


								</div>
                                <div class=\"panel-footer\">";

                                echo "<a class=\"btn btn-primary pull-right\" Onclick=\"VerificarServidor()\">".$_TRA['atualizar']."</a>";

								if($AdminStatusServer == "S"){
									echo "<a class=\"btn btn-danger pull-left\" Onclick=\"VerificarServidorConfig()\">".$_TRA['config']."</a>";
								}

                                echo "</div>
                            </div>";

						?>

                        </div>


                   	</div>

              </div>

  		<!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>
        <!-- END THIS PAGE PLUGINS-->

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->

        <script type='text/javascript'>
		CarregarTotal();

		function CarregarTotal(){
			$.post('CarregarTotal.php', function(resposta) {

				resposta = resposta.split('|');

				var ativo, esgotado, bloqueado, teste, ativos, esgotados, bloqueados, testes;
				ativo = resposta[0].trim();
				esgotado = resposta[1].trim();
				bloqueado = resposta[2].trim();
				teste = resposta[3].trim();

				ativos = ativo > 1 ? '<?php echo $_TRA['Ativos']; ?>' : '<?php echo $_TRA['Ativo']; ?>';
				esgotados = esgotado > 1 ? '<?php echo $_TRA['Esgotados']; ?>' : '<?php echo $_TRA['Esgotado']; ?>';
				bloqueados = bloqueado > 1 ? '<?php echo $_TRA['Bloqueados']; ?>' : '<?php echo $_TRA['Bloqueado']; ?>';
				testes = teste > 1 ? '<?php echo $_TRA['tas']; ?>' : '<?php echo $_TRA['ta']; ?>';

				$(".CountAtivos").html(ativo);
				$(".CountAtivosS").html(ativos);

				$(".CountEsgotados").html(esgotado);
				$(".CountEsgotadosS").html(esgotados);

				$(".CountBloqueados").html(bloqueado);
				$(".CountBloqueadosS").html(bloqueados);

				$(".CountTestes").html(teste);
				$(".CountTestesS").html(testes);

			});
		}

		function ConfigTeste(){

			panel_refresh($(".page-container"));

			$.post('ScriptModalTesteConfig.php', function(resposta) {

				setTimeout(panel_refresh($(".page-container")),500);

				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
			});
		}

		<?php
		if($AdminStatusServer == "S"){
		?>
		function VerificarServidorConfig(){

			panel_refresh($(".page-container"));

			$.post('ScriptModalStatusServer.php', function(resposta) {

				setTimeout(panel_refresh($(".page-container")),500);

				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
			});
		}
		<?php
		}
		?>

		function VerificarStatus(){

			$("#StatusVer").html("<center><img src=\"img/fileinput/loading.gif\"></center>");

			$.post('EnviarVerificarStatus.php', function(resposta) {
				$("#StatusVer").html('');
				$("#StatusVer").html(resposta);
			});
		}

		<?php
		if(empty($OperadoraPerfil)){
		?>
		VerOperadora();
		function VerOperadora(){

			$.post('EnviarVerificarPerfil.php', function(resposta) {
				$("#StatusOperadora").html('');
				$("#StatusOperadora").html(resposta);
			});
		}
		<?php
		}
		?>

		function VerificarOperadora(){

			panel_refresh($(".StatusBodyOP"));

			$.post('EnviarVerificarPerfil.php', function(resposta) {

				setTimeout(panel_refresh($(".StatusBodyOP")),500);

				$("#StatusOperadora").html('');
				$("#StatusOperadora").html(resposta);
			});
		}

		<?php
		if(empty($ServidorPerfil)){
		?>
		VerServidor()
		function VerServidor(){

			$.post('EnviarVerificarServidor.php', function(resposta) {
				$("#StatusServidor").html('');
				$("#StatusServidor").html(resposta);
			});
		}
		<?php
		}
		?>

		function VerificarServidor(){

			panel_refresh($(".StatusBodyServer"));

			$.post('EnviarVerificarServidor.php', function(resposta) {

				setTimeout(panel_refresh($(".StatusBodyServer")),500);

				$("#StatusServidor").html('');
				$("#StatusServidor").html(resposta);
			});
		}

        </script>


<?php
}else{
	echo Redirecionar('login.php');
}
?>