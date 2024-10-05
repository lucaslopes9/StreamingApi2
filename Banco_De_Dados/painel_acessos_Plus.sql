/*
Navicat MySQL Data Transfer

Source Server         : http://142.44.191.104/
Source Server Version : 50505
Source Host           : 142.44.191.104:3306
Source Database       : painel_acessos

Target Server Type    : MYSQL
Target Server Version : 50505
File Encoding         : 65001

Date: 2023-08-05 03:33:07
*/

SET FOREIGN_KEY_CHECKS=0;
-- ----------------------------
-- Table structure for `admin`
-- ----------------------------
DROP TABLE IF EXISTS `admin`;
CREATE TABLE `admin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `AdminVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `AdminAcesso` varchar(11) NOT NULL DEFAULT 'N',
  `AdminInfo` varchar(11) NOT NULL DEFAULT 'N',
  `AdminMensagem` varchar(11) NOT NULL DEFAULT 'N',
  `AdminBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `AdminDesativar` varchar(11) NOT NULL DEFAULT 'N',
  `AdminEditar` varchar(11) NOT NULL DEFAULT 'N',
  `AdminExcluir` varchar(11) NOT NULL DEFAULT 'N',
  `AdminAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `AdminLogin` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of admin
-- ----------------------------
INSERT INTO `admin` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `admin` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N');
INSERT INTO `admin` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `email_adicionar`
-- ----------------------------
DROP TABLE IF EXISTS `email_adicionar`;
CREATE TABLE `email_adicionar` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `EmailadicionarVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailadicionarAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailadicionarBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `EmailadicionarEditar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailadicionarExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_adicionar
-- ----------------------------
INSERT INTO `email_adicionar` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `email_adicionar` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `email_adicionar` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'S', 'S');

-- ----------------------------
-- Table structure for `email_modelo`
-- ----------------------------
DROP TABLE IF EXISTS `email_modelo`;
CREATE TABLE `email_modelo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `EmailModeloVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailModeloPreferencias` varchar(11) NOT NULL DEFAULT 'N',
  `EmailModeloAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailModeloBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `EmailModeloEditar` varchar(11) NOT NULL DEFAULT 'N',
  `EmailModeloExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_modelo
-- ----------------------------
INSERT INTO `email_modelo` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `email_modelo` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `email_modelo` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'S', 'S', 'S');

-- ----------------------------
-- Table structure for `imagemperfil`
-- ----------------------------
DROP TABLE IF EXISTS `imagemperfil`;
CREATE TABLE `imagemperfil` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `ImagemperfilVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `ImagemperfilAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `ImagemperfilExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of imagemperfil
-- ----------------------------
INSERT INTO `imagemperfil` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S');
INSERT INTO `imagemperfil` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N');
INSERT INTO `imagemperfil` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `noticias`
-- ----------------------------
DROP TABLE IF EXISTS `noticias`;
CREATE TABLE `noticias` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `NoticiaVisualizar` varchar(11) NOT NULL DEFAULT 'S',
  `NoticiaAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `NoticiaEditar` varchar(11) NOT NULL DEFAULT 'N',
  `NoticiaExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of noticias
-- ----------------------------
INSERT INTO `noticias` VALUES ('1', 'N', null, 'plustv', 'S', 'S', 'S', 'S');
INSERT INTO `noticias` VALUES ('18', 'S', '1', 'plustv', 'S', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `opcoes`
-- ----------------------------
DROP TABLE IF EXISTS `opcoes`;
CREATE TABLE `opcoes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `OpcoesExportar` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesImportar` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesVencimento` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesRelatorio` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesGrupoAcesso` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesMascaraURL` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesLiberarComputador` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesCircular` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesDesenvolvedor` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesStatusServer` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesBackup` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesEmailTemporario` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesEmailTeste` varchar(11) NOT NULL DEFAULT 'N',
  `OpcoesCupom` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of opcoes
-- ----------------------------
INSERT INTO `opcoes` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `opcoes` VALUES ('2', 'S', '1', 'plustv', 'N', 'S', 'N', 'S', 'N', 'S', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N');
INSERT INTO `opcoes` VALUES ('252', 'N', null, '759712-6931', 'N', 'S', 'N', 'S', 'N', 'S', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `pagamentos`
-- ----------------------------
DROP TABLE IF EXISTS `pagamentos`;
CREATE TABLE `pagamentos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `PagamentoPagSeguro` varchar(11) NOT NULL DEFAULT 'N',
  `PagamentoPayPal` varchar(11) NOT NULL DEFAULT 'N',
  `PagamentoMercadoPago` varchar(11) NOT NULL DEFAULT 'N',
  `PagamentoContaBancaria` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of pagamentos
-- ----------------------------
INSERT INTO `pagamentos` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S');
INSERT INTO `pagamentos` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N', 'S');
INSERT INTO `pagamentos` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N', 'S');

-- ----------------------------
-- Table structure for `perfil`
-- ----------------------------
DROP TABLE IF EXISTS `perfil`;
CREATE TABLE `perfil` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `PerfilVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `PerfilAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `PerfilBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `PerfilEditar` varchar(11) NOT NULL DEFAULT 'N',
  `PerfilExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of perfil
-- ----------------------------
INSERT INTO `perfil` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `perfil` VALUES ('2', 'S', '1', 'plustv', 'S', 'N', 'N', 'N', 'N');
INSERT INTO `perfil` VALUES ('252', 'N', null, '759712-6931', 'S', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `rev`
-- ----------------------------
DROP TABLE IF EXISTS `rev`;
CREATE TABLE `rev` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `RevVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `RevAcesso` varchar(11) NOT NULL DEFAULT 'N',
  `RevInfo` varchar(11) NOT NULL DEFAULT 'N',
  `RevMensagem` varchar(11) NOT NULL DEFAULT 'N',
  `RevBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `RevDesativar` varchar(11) NOT NULL DEFAULT 'N',
  `RevEditar` varchar(11) NOT NULL DEFAULT 'N',
  `RevExcluir` varchar(11) NOT NULL DEFAULT 'N',
  `RevAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `RevUrldeTeste` varchar(11) NOT NULL DEFAULT 'N',
  `RevLogin` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of rev
-- ----------------------------
INSERT INTO `rev` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `rev` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `rev` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');

-- ----------------------------
-- Table structure for `servidorcsp`
-- ----------------------------
DROP TABLE IF EXISTS `servidorcsp`;
CREATE TABLE `servidorcsp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `ServidorcspVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspConfig` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspInfo` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspEditar` varchar(11) NOT NULL DEFAULT 'N',
  `ServidorcspExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of servidorcsp
-- ----------------------------
INSERT INTO `servidorcsp` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `servidorcsp` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N', 'N', 'N', 'N', 'N');
INSERT INTO `servidorcsp` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `sms_adicionar`
-- ----------------------------
DROP TABLE IF EXISTS `sms_adicionar`;
CREATE TABLE `sms_adicionar` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `SMSadicionarVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSadicionarAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSadicionarBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `SMSadicionarEditar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSadicionarExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms_adicionar
-- ----------------------------
INSERT INTO `sms_adicionar` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `sms_adicionar` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N', 'N', 'N');
INSERT INTO `sms_adicionar` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `sms_modelo`
-- ----------------------------
DROP TABLE IF EXISTS `sms_modelo`;
CREATE TABLE `sms_modelo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `SMSModeloVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSModeloPreferencias` varchar(11) NOT NULL DEFAULT 'N',
  `SMSModeloAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSModeloBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `SMSModeloEditar` varchar(11) NOT NULL DEFAULT 'N',
  `SMSModeloExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms_modelo
-- ----------------------------
INSERT INTO `sms_modelo` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `sms_modelo` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N', 'N', 'N', 'N');
INSERT INTO `sms_modelo` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `sms_saldo`
-- ----------------------------
DROP TABLE IF EXISTS `sms_saldo`;
CREATE TABLE `sms_saldo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `SaldoVisualizar` varchar(11) NOT NULL DEFAULT 'S',
  `SaldoAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `SaldoEditar` varchar(11) NOT NULL DEFAULT 'N',
  `SaldoExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms_saldo
-- ----------------------------
INSERT INTO `sms_saldo` VALUES ('1', 'N', null, 'plustv', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `status`
-- ----------------------------
DROP TABLE IF EXISTS `status`;
CREATE TABLE `status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `StatusOnline` varchar(11) NOT NULL DEFAULT 'N',
  `StatusDesconectado` varchar(11) NOT NULL DEFAULT 'N',
  `StatusFalhado` varchar(11) NOT NULL DEFAULT 'N',
  `StatusLogs` varchar(11) NOT NULL DEFAULT 'N',
  `StatusReshare` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of status
-- ----------------------------
INSERT INTO `status` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `status` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'S', 'N');
INSERT INTO `status` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'S', 'N');

-- ----------------------------
-- Table structure for `template`
-- ----------------------------
DROP TABLE IF EXISTS `template`;
CREATE TABLE `template` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `TemplateTema` varchar(11) NOT NULL DEFAULT 'N',
  `TemplateInfo` varchar(11) NOT NULL DEFAULT 'N',
  `TemplatePParede` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of template
-- ----------------------------
INSERT INTO `template` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S');
INSERT INTO `template` VALUES ('2', 'S', '1', 'plustv', 'N', 'N', 'N');
INSERT INTO `template` VALUES ('252', 'N', null, '759712-6931', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `tempoteste`
-- ----------------------------
DROP TABLE IF EXISTS `tempoteste`;
CREATE TABLE `tempoteste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `TesteTempoVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `TesteTempoAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `TesteTempoExcluir` varchar(11) NOT NULL DEFAULT 'N',
  `TesteTempoBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `TesteTempoEditar` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of tempoteste
-- ----------------------------
INSERT INTO `tempoteste` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `tempoteste` VALUES ('2', 'S', '1', 'plustv', 'S', 'N', 'N', 'N', 'N');
INSERT INTO `tempoteste` VALUES ('252', 'N', null, '759712-6931', 'S', 'N', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `teste`
-- ----------------------------
DROP TABLE IF EXISTS `teste`;
CREATE TABLE `teste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `TesteVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `TesteInfo` varchar(11) NOT NULL DEFAULT 'N',
  `TesteMensagem` varchar(11) NOT NULL DEFAULT 'N',
  `TesteBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `TesteEditar` varchar(11) NOT NULL DEFAULT 'N',
  `TesteExcluir` varchar(11) NOT NULL DEFAULT 'N',
  `TesteAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `TesteLogin` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of teste
-- ----------------------------
INSERT INTO `teste` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `teste` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `teste` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');

-- ----------------------------
-- Table structure for `user`
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `UserVisualizar` varchar(11) NOT NULL DEFAULT 'N',
  `UserInfo` varchar(11) NOT NULL DEFAULT 'N',
  `UserMensagem` varchar(11) NOT NULL DEFAULT 'N',
  `UserBloquear` varchar(11) NOT NULL DEFAULT 'N',
  `UserEditar` varchar(11) NOT NULL DEFAULT 'N',
  `UserExcluir` varchar(11) NOT NULL DEFAULT 'N',
  `UserAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `UserLogin` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=253 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', 'N', '0', 'plustv', 'S', 'S', 'S', 'S', 'S', 'S', 'S', 'S');
INSERT INTO `user` VALUES ('2', 'S', '1', 'plustv', 'S', 'S', 'S', 'N', 'S', 'N', 'S', 'S');
INSERT INTO `user` VALUES ('252', 'N', null, '759712-6931', 'S', 'S', 'S', 'N', 'S', 'N', 'S', 'S');

-- ----------------------------
-- Table structure for `whatsapp_adicionar`
-- ----------------------------
DROP TABLE IF EXISTS `whatsapp_adicionar`;
CREATE TABLE `whatsapp_adicionar` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `whatVisualizar` varchar(11) NOT NULL DEFAULT 'S',
  `whatAdicionar` varchar(11) NOT NULL DEFAULT 'N',
  `whatEditar` varchar(11) NOT NULL DEFAULT 'N',
  `whatExcluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of whatsapp_adicionar
-- ----------------------------
INSERT INTO `whatsapp_adicionar` VALUES ('1', 'N', null, 'plustv', 'S', 'S', 'S', 'S');
INSERT INTO `whatsapp_adicionar` VALUES ('18', 'S', '1', 'plustv', 'S', 'N', 'N', 'N');

-- ----------------------------
-- Table structure for `whatsapp_saldo`
-- ----------------------------
DROP TABLE IF EXISTS `whatsapp_saldo`;
CREATE TABLE `whatsapp_saldo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `grupo` varchar(11) NOT NULL DEFAULT 'N',
  `id_grupo` int(11) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `Visualizar` varchar(11) NOT NULL DEFAULT 'S',
  `Adicionar` varchar(11) NOT NULL DEFAULT 'N',
  `Editar` varchar(11) NOT NULL DEFAULT 'N',
  `Excluir` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of whatsapp_saldo
-- ----------------------------
INSERT INTO `whatsapp_saldo` VALUES ('1', 'N', null, 'plustv', 'S', 'S', 'S', 'S');
